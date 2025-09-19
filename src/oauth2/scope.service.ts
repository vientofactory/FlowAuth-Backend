import { Injectable, OnApplicationBootstrap, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Scope } from '../scope/scope.entity';

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
  ) {}

  async onApplicationBootstrap() {
    await this.loadScopesToCache();
  }

  private async loadScopesToCache(): Promise<void> {
    try {
      this.logger.log('Loading scopes to memory cache...');

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

      this.cacheInitialized = true;
      this.logger.log(`Loaded ${scopes.length} scopes to memory cache`);
    } catch (error) {
      this.logger.error('Failed to load scopes to cache:', error);
      throw error;
    }
  }

  /**
   * 캐시를 수동으로 갱신하는 메서드
   */
  async refreshCache(): Promise<void> {
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
    return [...this.allScopesCache]; // 배열 복사본 반환
  }

  async findDefaultScopes(): Promise<Scope[]> {
    await this.ensureCacheInitialized();
    return [...this.defaultScopesCache]; // 배열 복사본 반환
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
    return this.scopeCache.get(name) || null;
  }
}
