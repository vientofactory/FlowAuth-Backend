import {
  Injectable,
  OnApplicationBootstrap,
  Logger,
  Inject,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import type { Cache } from 'cache-manager';
import { Scope } from './scope.entity';

@Injectable()
export class ScopeService implements OnApplicationBootstrap {
  private readonly logger = new Logger(ScopeService.name);
  private scopeCache: Map<string, Scope> = new Map();
  private allScopesCache: Scope[] = [];
  private defaultScopesCache: Scope[] = [];
  private cacheInitialized = false;

  constructor(
    @InjectRepository(Scope)
    private readonly scopeRepository: Repository<Scope>,
    @Inject(CACHE_MANAGER) private readonly cacheManager: Cache,
  ) {}

  async onApplicationBootstrap() {
    // 기본 스코프들 초기화 (없는 경우에만 생성)
    await this.initializeDefaultScopes();

    // 캐시 로드
    await this.loadScopesToCache();
  }

  private async loadScopesToCache(): Promise<void> {
    try {
      this.logger.log('Loading scopes to memory and Redis cache...');

      const scopes = await this.scopeRepository.find({
        where: { isActive: true },
        order: { name: 'ASC' },
      });

      // 캐시 초기화
      this.scopeCache.clear();
      this.allScopesCache = [];
      this.defaultScopesCache = [];

      // 캐시에 데이터 로드
      scopes.forEach((scope) => {
        this.scopeCache.set(scope.name, scope);
        this.allScopesCache.push(scope);

        if (scope.isDefault) {
          this.defaultScopesCache.push(scope);
        }
      });

      // Redis에 캐시 저장 (TTL: 1시간)
      await this.cacheManager.set('scopes:all', this.allScopesCache, 3600000);
      await this.cacheManager.set(
        'scopes:default',
        this.defaultScopesCache,
        3600000,
      );

      // 개별 스코프도 캐시
      for (const scope of scopes) {
        await this.cacheManager.set(
          `scopes:name:${scope.name}`,
          scope,
          3600000,
        );
      }

      this.cacheInitialized = true;
      this.logger.log(
        `Loaded ${scopes.length} scopes to memory and Redis cache`,
      );
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
    await this.cacheManager.del('scopes:all');
    await this.cacheManager.del('scopes:default');

    // 모든 개별 스코프 캐시 삭제 (와일드카드 삭제는 Redis에서 지원하지 않으므로 메모리에서 추적)
    // 실제 운영에서는 Redis SCAN 명령이나 별도의 캐시 키 관리가 필요할 수 있음

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
      const scope = this.scopeCache.get(name);
      if (scope) {
        foundScopes.push(scope);
      }
    }

    return foundScopes;
  }

  async findAll(): Promise<Scope[]> {
    await this.ensureCacheInitialized();

    // Redis 캐시에서 먼저 확인
    const cachedScopes = await this.cacheManager.get<Scope[]>('scopes:all');
    if (cachedScopes) {
      return cachedScopes;
    }

    // 캐시에 없으면 메모리 캐시에서 반환
    return [...this.allScopesCache];
  }

  async findDefaultScopes(): Promise<Scope[]> {
    await this.ensureCacheInitialized();

    // Redis 캐시에서 먼저 확인
    const cachedDefaultScopes =
      await this.cacheManager.get<Scope[]>('scopes:default');
    if (cachedDefaultScopes) {
      return cachedDefaultScopes;
    }

    // 캐시에 없으면 메모리 캐시에서 반환
    return [...this.defaultScopesCache];
  }

  async validateScopes(scopeNames: string[]): Promise<boolean> {
    if (scopeNames.length === 0) {
      return true;
    }

    await this.ensureCacheInitialized();

    for (const scopeName of scopeNames) {
      if (!this.scopeCache.has(scopeName)) {
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
  getCacheInfo(): {
    initialized: boolean;
    totalScopes: number;
    defaultScopes: number;
    cacheSize: number;
  } {
    return {
      initialized: this.cacheInitialized,
      totalScopes: this.allScopesCache.length,
      defaultScopes: this.defaultScopesCache.length,
      cacheSize: this.scopeCache.size,
    };
  }

  /**
   * 특정 스코프가 캐시에 있는지 확인
   */
  async hasScope(name: string): Promise<boolean> {
    await this.ensureCacheInitialized();
    return this.scopeCache.has(name);
  }

  /**
   * 스코프 이름으로 스코프 정보 조회 (캐시 사용)
   */
  async findByName(name: string): Promise<Scope | null> {
    await this.ensureCacheInitialized();

    // Redis 캐시에서 먼저 확인
    const cachedScope = await this.cacheManager.get<Scope>(
      `scopes:name:${name}`,
    );
    if (cachedScope) {
      return cachedScope;
    }

    // 캐시에 없으면 메모리 캐시에서 반환
    return this.scopeCache.get(name) || null;
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
