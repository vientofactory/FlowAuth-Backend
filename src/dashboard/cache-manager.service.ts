import { Injectable, Inject } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import type { Cache } from 'cache-manager';
import { User } from '../auth/user.entity';
import { CACHE_KEYS, DASHBOARD_CONFIG } from './dashboard.constants';

// Redis 클라이언트 인터페이스 정의
interface RedisClient {
  scan(
    cursor: string,
    ...args: (
      | string
      | number
      | ((err: Error | null, reply: [string, string[]]) => void)
    )[]
  ): void;
  del(keys: string[], callback: (err: Error | null) => void): void;
}

// Cache store 인터페이스 정의
interface CacheStore {
  client?: RedisClient;
}

@Injectable()
export class CacheManagerService {
  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
    @Inject(CACHE_MANAGER)
    private cacheManager: Cache,
  ) {}

  /**
   * 사용자 통계 캐시 무효화
   */
  async invalidateUserStatsCache(userId: number): Promise<void> {
    try {
      const cacheKey = CACHE_KEYS.stats(userId);
      await this.cacheManager.del(cacheKey);
    } catch (error) {
      console.warn('Failed to invalidate user stats cache:', error);
    }
  }

  /**
   * 사용자 활동 캐시 무효화
   */
  async invalidateUserActivitiesCache(userId: number): Promise<void> {
    try {
      // 활동 캐시는 다양한 limit으로 저장될 수 있으므로 패턴으로 삭제
      const commonLimits = [5, 10, 20, 50];
      await Promise.all(
        commonLimits.map((limit) =>
          this.cacheManager.del(CACHE_KEYS.activities(userId, limit)),
        ),
      );
    } catch (error) {
      console.warn('Failed to invalidate user activities cache:', error);
    }
  }

  /**
   * 사용자 프로필 캐시 무효화
   */
  async invalidateUserProfileCache(userId: number): Promise<void> {
    try {
      const cacheKey = CACHE_KEYS.user(userId);
      await this.cacheManager.del(cacheKey);
    } catch (error) {
      console.warn('Failed to invalidate user profile cache:', error);
    }
  }

  /**
   * 사용자 권한 캐시 무효화
   */
  async invalidateUserPermissionsCache(userId: number): Promise<void> {
    try {
      const cacheKey = CACHE_KEYS.permissions(userId);
      await this.cacheManager.del(cacheKey);
    } catch (error) {
      console.warn('Failed to invalidate user permissions cache:', error);
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
    ]);
  }

  /**
   * 모든 사용자 캐시 무효화 (Redis SCAN 방식 사용)
   */
  async invalidateAllUsersCache(): Promise<void> {
    try {
      // Redis SCAN을 사용하여 모든 사용자 캐시 키를 찾아서 삭제
      // 패턴: {prefix}:* 형식

      const patterns = [
        `${DASHBOARD_CONFIG.CACHE.KEY_PREFIX.STATS}:*`,
        `${DASHBOARD_CONFIG.CACHE.KEY_PREFIX.ACTIVITIES}:*:*`,
        `${DASHBOARD_CONFIG.CACHE.KEY_PREFIX.USER}:*`,
        `${DASHBOARD_CONFIG.CACHE.KEY_PREFIX.PERMISSIONS}:*`,
      ];

      for (const pattern of patterns) {
        await this.deleteKeysByPattern(pattern);
      }
    } catch (error) {
      console.error('Failed to invalidate all users cache:', error);
      // SCAN 실패 시 폴백으로 기존 방식 사용
      this.invalidateAllUsersCacheFallback();
    }
  }

  /**
   * 패턴에 맞는 모든 캐시 키 삭제 (Redis SCAN 사용)
   */
  private async deleteKeysByPattern(pattern: string): Promise<void> {
    try {
      // Redis 클라이언트에 안전하게 접근
      const cacheStore = (
        this.cacheManager as unknown as { store?: CacheStore }
      ).store;

      if (!cacheStore?.client) {
        console.warn('Redis client not available, skipping pattern deletion');
        return;
      }

      const redisClient = cacheStore.client;

      return new Promise<void>((resolve, reject) => {
        const keysToDelete: string[] = [];
        let cursor = '0';

        const scanAndDelete = () => {
          redisClient.scan(
            cursor,
            'MATCH',
            pattern,
            'COUNT',
            100,
            (err: Error | null, reply: [string, string[]]) => {
              if (err) {
                reject(err);
                return;
              }

              cursor = reply[0];
              const keys = reply[1];

              // 찾은 키들을 삭제 목록에 추가
              keysToDelete.push(...keys);

              // 모든 키를 스캔했으면 삭제 실행
              if (cursor === '0') {
                if (keysToDelete.length > 0) {
                  redisClient.del(keysToDelete, (delErr: Error | null) => {
                    if (delErr) {
                      reject(delErr);
                    } else {
                      console.log(
                        `Deleted ${keysToDelete.length} cache keys with pattern: ${pattern}`,
                      );
                      resolve();
                    }
                  });
                } else {
                  resolve();
                }
              } else {
                // 다음 배치를 스캔
                scanAndDelete();
              }
            },
          );
        };

        scanAndDelete();
      });
    } catch (error) {
      console.warn(`Failed to delete keys with pattern ${pattern}:`, error);
      // SCAN 실패 시 조용히 무시
    }
  }

  /**
   * 폴백 방식: 데이터베이스에서 모든 사용자 조회 후 개별 삭제
   */
  private invalidateAllUsersCacheFallback(): void {
    console.log('Using fallback cache invalidation method');

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

        Promise.all(cacheDeletePromises).catch((error) => {
          console.warn('Failed to invalidate some caches:', error);
        });
      })
      .catch((error) => {
        console.error('Failed to get users for cache invalidation:', error);
      });
  }

  /**
   * 캐시 키 존재 여부 확인
   */
  async hasCacheKey(key: string): Promise<boolean> {
    try {
      const value = await this.cacheManager.get(key);
      return value !== undefined;
    } catch {
      return false;
    }
  }

  /**
   * 캐시에서 값 가져오기
   */
  async getCacheValue<T>(key: string): Promise<T | undefined> {
    try {
      return await this.cacheManager.get<T>(key);
    } catch {
      return undefined;
    }
  }

  /**
   * 캐시에 값 설정하기
   */
  async setCacheValue<T>(key: string, value: T, ttl?: number): Promise<void> {
    try {
      await this.cacheManager.set(key, value, ttl);
    } catch {
      console.warn('Failed to set cache value');
    }
  }
}
