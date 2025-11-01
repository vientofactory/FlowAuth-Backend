import { Injectable, Inject, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import Redis from 'ioredis';
import { User } from '../auth/user.entity';
import { CACHE_KEYS as DASHBOARD_CACHE_KEYS } from '../dashboard/dashboard.constants';
import {
  CACHE_KEYS,
  CACHE_INVALIDATION_PATTERNS,
} from '../constants/cache.constants';

@Injectable()
export class CacheManagerService {
  private readonly logger = new Logger(CacheManagerService.name);

  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
    @Inject('REDIS_CLIENT') private readonly redisClient: Redis,
  ) {}

  /**
   * 사용자 통계 캐시 무효화
   */
  async invalidateUserStatsCache(userId: number): Promise<void> {
    try {
      const cacheKey = DASHBOARD_CACHE_KEYS.dashboard.stats(userId);
      await this.redisClient.del(cacheKey);
    } catch (error) {
      this.logger.warn('Failed to invalidate user stats cache:', error);
    }
  }

  /**
   * 사용자 활동 캐시 무효화
   */
  async invalidateUserActivitiesCache(userId: number): Promise<void> {
    try {
      const cacheKey = DASHBOARD_CACHE_KEYS.dashboard.activities(userId);
      await this.redisClient.del(cacheKey);
    } catch (error) {
      this.logger.warn('Failed to invalidate user activities cache:', error);
    }
  }

  /**
   * 사용자 프로필 캐시 무효화
   */
  async invalidateUserProfileCache(userId: number): Promise<void> {
    try {
      const cacheKey = CACHE_KEYS.profile.user(userId);
      await this.redisClient.del(cacheKey);
    } catch (error) {
      this.logger.warn('Failed to invalidate user profile cache:', error);
    }
  }

  /**
   * 사용자 권한 캐시 무효화
   */
  async invalidateUserPermissionsCache(userId: number): Promise<void> {
    try {
      const cacheKey = DASHBOARD_CACHE_KEYS.dashboard.permissions(userId);
      await this.redisClient.del(cacheKey);
    } catch (error) {
      this.logger.warn('Failed to invalidate user permissions cache:', error);
    }
  }

  /**
   * 사용자 OAuth2 캐시 무효화 (클라이언트 등)
   */
  async invalidateUserOAuth2Cache(userId: number): Promise<void> {
    try {
      const cacheKey = CACHE_KEYS.oauth2.clients.byUser(userId);
      await this.redisClient.del(cacheKey);
    } catch (error) {
      this.logger.warn('Failed to invalidate user OAuth2 cache:', error);
    }
  }

  /**
   * 특정 사용자의 모든 캐시 무효화
   */
  async invalidateAllUserCache(userId: number): Promise<void> {
    await Promise.all([
      this.invalidateUserStatsCache(userId),
      this.invalidateUserActivitiesCache(userId),
      this.invalidateUserProfileCache(userId),
      this.invalidateUserPermissionsCache(userId),
      this.invalidateUserOAuth2Cache(userId),
    ]);
  }

  /**
   * 모든 사용자 캐시 무효화
   */
  async invalidateAllUsersCache(): Promise<void> {
    try {
      // 사용자별 캐시 패턴을 사용하여 모든 사용자 캐시 무효화
      const userCachePatterns = CACHE_INVALIDATION_PATTERNS.user(0); // userId 0은 패턴용

      for (const pattern of userCachePatterns) {
        await this.deleteKeysByPattern(pattern);
      }
    } catch (error) {
      this.logger.error('Failed to invalidate all users cache:', error);
      // SCAN 실패 시 폴백으로 기존 방식 사용
      this.invalidateAllUsersCacheFallback();
    }
  }

  /**
   * 패턴에 맞는 모든 캐시 키 삭제
   */
  private async deleteKeysByPattern(pattern: string): Promise<void> {
    try {
      const keysToDelete: string[] = [];
      let cursor = '0';

      do {
        const [newCursor, keys] = await this.redisClient.scan(
          cursor,
          'MATCH',
          pattern,
          'COUNT',
          100,
        );
        cursor = newCursor;
        keysToDelete.push(...keys);
      } while (cursor !== '0');

      if (keysToDelete.length > 0) {
        await this.redisClient.del(keysToDelete);
        this.logger.log(
          `Deleted ${keysToDelete.length} cache keys with pattern: ${pattern}`,
        );
      }
    } catch (error) {
      this.logger.warn(`Failed to delete keys with pattern ${pattern}:`, error);
    }
  }

  /**
   * 폴백 방식: 데이터베이스에서 모든 사용자 조회 후 개별 삭제
   */
  private invalidateAllUsersCacheFallback(): void {
    this.logger.log('Using fallback cache invalidation method');

    this.userRepository
      .find({
        select: ['id'],
      })
      .then((users) => {
        const cacheDeletePromises = users.flatMap((user) => {
          const userId = user.id;
          return [
            this.invalidateUserStatsCache(userId),
            this.invalidateUserActivitiesCache(userId),
            this.invalidateUserProfileCache(userId),
            this.invalidateUserPermissionsCache(userId),
          ];
        });

        void Promise.all(cacheDeletePromises).catch((error) => {
          this.logger.warn('Failed to invalidate some caches:', error);
        });
      })
      .catch((error) => {
        this.logger.error('Failed to get users for cache invalidation:', error);
      });
  }

  /**
   * 캐시 키 존재 여부 확인
   */
  async hasCacheKey(key: string): Promise<boolean> {
    try {
      const value = await this.redisClient.get(key);
      return value !== null;
    } catch {
      return false;
    }
  }

  /**
   * 캐시에서 값 가져오기
   */
  async getCacheValue<T>(key: string): Promise<T | undefined> {
    try {
      const value = await this.redisClient.get(key);
      return value ? (JSON.parse(value) as T) : undefined;
    } catch {
      return undefined;
    }
  }

  /**
   * 캐시에 값 설정하기
   */
  async setCacheValue<T>(key: string, value: T, ttl?: number): Promise<void> {
    try {
      const serializedValue = JSON.stringify(value);
      if (ttl) {
        await this.redisClient.setex(key, ttl, serializedValue);
      } else {
        await this.redisClient.set(key, serializedValue);
      }
    } catch {
      this.logger.warn('Failed to set cache value');
    }
  }

  /**
   * 캐시에서 키 삭제하기
   */
  async delCacheKey(key: string): Promise<void> {
    try {
      await this.redisClient.del(key);
    } catch {
      this.logger.warn('Failed to delete cache key');
    }
  }
}
