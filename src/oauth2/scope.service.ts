import {
  Injectable,
  OnApplicationBootstrap,
  Logger,
  Inject,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import Redis from 'ioredis';
import { CACHE_CONFIG, CACHE_KEYS } from '../constants/cache.constants';
import { Scope } from './scope.entity';

@Injectable()
export class ScopeService implements OnApplicationBootstrap {
  private readonly logger = new Logger(ScopeService.name);
  private cacheInitialized = false;

  constructor(
    @InjectRepository(Scope)
    private readonly scopeRepository: Repository<Scope>,
    @Inject('REDIS_CLIENT') private readonly redisClient: Redis,
  ) {}

  async onApplicationBootstrap() {
    // 기본 스코프들 초기화 (없는 경우에만 생성)
    await this.initializeDefaultScopes();

    // 캐시 로드
    await this.loadScopesToCache();
  }

  private async loadScopesToCache(): Promise<void> {
    try {
      this.logger.log('Loading scopes to Redis cache...');

      const scopes = await this.scopeRepository.find({
        where: { isActive: true },
        order: { name: 'ASC' },
      });

      // Redis에 캐시 저장 (TTL: 1시간)
      await this.redisClient.setex(
        CACHE_KEYS.oauth2.scopes.all(),
        CACHE_CONFIG.TTL.SCOPES_ALL,
        JSON.stringify(scopes),
      );
      await this.redisClient.setex(
        'scopes:default',
        CACHE_CONFIG.TTL.SCOPES_ALL,
        JSON.stringify(scopes.filter((s) => s.isDefault)),
      );

      // 개별 스코프도 캐시
      for (const scope of scopes) {
        await this.redisClient.setex(
          `scopes:name:${scope.name}`,
          3600000,
          JSON.stringify(scope),
        );
      }

      this.cacheInitialized = true;
      this.logger.log(`Loaded ${scopes.length} scopes to Redis cache`);
    } catch (error) {
      this.logger.error('Failed to load scopes to cache:', error);
      throw error;
    }
  }

  /**
   * 캐시를 수동으로 갱신하는 메서드
   */
  async refreshCache(): Promise<void> {
    // 기존 Redis 캐시 삭제
    await this.redisClient.del('scopes:all');
    await this.redisClient.del('scopes:default');

    // 모든 개별 스코프 캐시 삭제 (패턴 삭제)
    const keys = await this.redisClient.keys('scopes:name:*');
    if (keys.length > 0) {
      await this.redisClient.del(...keys);
    }

    await this.loadScopesToCache();
  }

  /**
   * 캐시가 초기화되었는지 확인하고, 초기화되지 않았다면 DB에서 조회
   */
  private async ensureCacheInitialized(): Promise<void> {
    if (!this.cacheInitialized) {
      await this.loadScopesToCache();
    }
  }

  async createScope(
    name: string,
    description: string,
    isDefault = false,
  ): Promise<Scope> {
    const scope = this.scopeRepository.create({
      name,
      description,
      isDefault,
    });

    const savedScope = await this.scopeRepository.save(scope);

    // 캐시 갱신
    await this.refreshCache();

    return savedScope;
  }

  async findByNames(names: string[]): Promise<Scope[]> {
    if (names.length === 0) {
      return [];
    }

    await this.ensureCacheInitialized();

    const foundScopes: Scope[] = [];
    for (const name of names) {
      const cachedScope = await this.redisClient.get(`scopes:name:${name}`);
      if (cachedScope) {
        foundScopes.push(JSON.parse(cachedScope) as Scope);
      }
    }

    return foundScopes;
  }

  async findAll(): Promise<Scope[]> {
    await this.ensureCacheInitialized();

    // Redis 캐시에서 먼저 확인
    const cachedScopes = await this.redisClient.get(
      CACHE_KEYS.oauth2.scopes.all(),
    );
    if (cachedScopes) {
      return JSON.parse(cachedScopes) as Scope[];
    }

    // 캐시에 없으면 DB에서 조회 후 캐시
    const scopes = await this.scopeRepository.find({
      where: { isActive: true },
      order: { name: 'ASC' },
    });
    await this.redisClient.setex(
      CACHE_KEYS.oauth2.scopes.all(),
      CACHE_CONFIG.TTL.SCOPES_ALL,
      JSON.stringify(scopes),
    );
    return scopes;
  }

  async findDefaultScopes(): Promise<Scope[]> {
    await this.ensureCacheInitialized();

    // Redis 캐시에서 먼저 확인
    const cachedDefaultScopes = await this.redisClient.get('scopes:default');
    if (cachedDefaultScopes) {
      return JSON.parse(cachedDefaultScopes) as Scope[];
    }

    // 캐시에 없으면 DB에서 조회 후 캐시
    const defaultScopes = await this.scopeRepository.find({
      where: { isActive: true, isDefault: true },
      order: { name: 'ASC' },
    });
    await this.redisClient.setex(
      'scopes:default',
      CACHE_CONFIG.TTL.SCOPES_ALL,
      JSON.stringify(defaultScopes),
    );
    return defaultScopes;
  }

  async validateScopes(scopeNames: string[]): Promise<boolean> {
    if (scopeNames.length === 0) {
      return true;
    }

    await this.ensureCacheInitialized();

    for (const scopeName of scopeNames) {
      const exists = await this.redisClient.exists(`scopes:name:${scopeName}`);
      if (!exists) {
        return false;
      }
    }

    return true;
  }

  /**
   * 스코프 업데이트 (캐시도 함께 갱신)
   */
  async updateScope(
    name: string,
    updates: Partial<Pick<Scope, 'description' | 'isDefault' | 'isActive'>>,
  ): Promise<Scope | null> {
    const scope = await this.scopeRepository.findOne({ where: { name } });
    if (!scope) {
      return null;
    }

    Object.assign(scope, updates);
    const updatedScope = await this.scopeRepository.save(scope);

    // 캐시 갱신
    await this.refreshCache();

    return updatedScope;
  }

  /**
   * 스코프 삭제 (소프트 삭제 - isActive를 false로 설정)
   */
  async deleteScope(name: string): Promise<boolean> {
    const result = await this.scopeRepository.update(
      { name },
      { isActive: false },
    );

    if (result.affected && result.affected > 0) {
      // 캐시 갱신
      await this.refreshCache();
      return true;
    }

    return false;
  }

  /**
   * 캐시 상태 정보 반환 (디버깅용)
   */
  async getCacheInfo(): Promise<{
    initialized: boolean;
    totalScopes: number;
    defaultScopes: number;
    cacheKeys: string[];
  }> {
    const allScopes = await this.redisClient.get(
      CACHE_KEYS.oauth2.scopes.all(),
    );
    const defaultScopes = await this.redisClient.get('scopes:default');
    const keys = await this.redisClient.keys('scopes:*');

    return {
      initialized: this.cacheInitialized,
      totalScopes: allScopes ? (JSON.parse(allScopes) as Scope[]).length : 0,
      defaultScopes: defaultScopes
        ? (JSON.parse(defaultScopes) as Scope[]).length
        : 0,
      cacheKeys: keys,
    };
  }

  /**
   * 특정 스코프가 캐시에 있는지 확인
   */
  async hasScope(name: string): Promise<boolean> {
    await this.ensureCacheInitialized();
    const exists = await this.redisClient.exists(`scopes:name:${name}`);
    return exists === 1;
  }

  /**
   * 스코프 이름으로 스코프 정보 조회 (캐시 사용)
   */
  async findByName(name: string): Promise<Scope | null> {
    await this.ensureCacheInitialized();

    // Redis 캐시에서 먼저 확인
    const cachedScope = await this.redisClient.get(`scopes:name:${name}`);
    if (cachedScope) {
      return JSON.parse(cachedScope) as Scope;
    }

    // 캐시에 없으면 DB에서 조회 후 캐시
    const scope = await this.scopeRepository.findOne({
      where: { name, isActive: true },
    });
    if (scope) {
      await this.redisClient.setex(
        `scopes:name:${name}`,
        3600000,
        JSON.stringify(scope),
      );
    }
    return scope;
  }

  /**
   * 레거시 OAuth2 스코프들을 새로운 스코프들로 변환
   * @param scopeNames 요청된 스코프 이름들
   * @returns 변환된 스코프 이름들
   */
  normalizeScopes(scopeNames: string[]): string[] {
    const normalizedScopes: string[] = [];
    const scopeSet = new Set<string>();

    for (const scopeName of scopeNames) {
      // 레거시 스코프 매핑
      const mappedScope = this.mapLegacyScope(scopeName);

      if (!scopeSet.has(mappedScope)) {
        scopeSet.add(mappedScope);
        normalizedScopes.push(mappedScope);
      }
    }

    return normalizedScopes;
  }

  /**
   * 레거시 스코프를 새로운 스코프로 매핑
   * @param scopeName 원래 스코프 이름
   * @returns 매핑된 스코프 이름
   */
  private mapLegacyScope(scopeName: string): string {
    // 레거시 스코프 매핑 테이블
    const legacyScopeMapping: Record<string, string> = {
      basic: 'profile',
      'read:user': 'profile',
      'read:profile': 'profile',
      identify: 'profile', // identify 레거시 스코프를 profile로 매핑
      email: 'email',
      openid: 'openid',
    };

    // Safe object access to prevent injection
    return Object.prototype.hasOwnProperty.call(legacyScopeMapping, scopeName)
      ? // eslint-disable-next-line security/detect-object-injection
        legacyScopeMapping[scopeName]
      : scopeName;
  }

  /**
   * 기본 스코프들을 데이터베이스에 초기화
   */
  async initializeDefaultScopes(): Promise<void> {
    const defaultScopes = [
      {
        name: 'openid',
        description: 'OpenID Connect 인증을 위한 기본 스코프',
        isDefault: true,
        isActive: true,
      },
      {
        name: 'profile',
        description: '사용자 프로필 정보 (이름, 생년월일, 지역, 사진 등) 접근',
        isDefault: true,
        isActive: true,
      },
      {
        name: 'email',
        description: '사용자 이메일 주소 접근',
        isDefault: false,
        isActive: true,
      },
    ];

    for (const scopeData of defaultScopes) {
      const existingScope = await this.scopeRepository.findOne({
        where: { name: scopeData.name },
      });

      if (!existingScope) {
        await this.scopeRepository.save(scopeData);
        this.logger.log(`Created default scope: ${scopeData.name}`);
      }
    }

    // 캐시 리프레시
    await this.loadScopesToCache();
  }
}
