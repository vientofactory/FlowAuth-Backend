import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, LessThan } from 'typeorm';
import { Client } from '../oauth2/client.entity';
import { User } from '../auth/user.entity';
import { Token } from '../oauth2/token.entity';
import { TokenService } from '../oauth2/token.service';
import { TOKEN_TYPES } from '../constants/auth.constants';
import { CacheManagerService } from './cache-manager.service';
import { DASHBOARD_CONFIG } from './dashboard.constants';

interface RawTokenStats {
  hour?: string;
  date?: string;
  clientName?: string;
  tokenCount?: string | number;
  count?: string | number;
  total?: string | number;
}

/**
 * 대시보드 통계 서비스에서 발생할 수 있는 에러 타입들
 */
export class DashboardStatsError extends Error {
  constructor(
    message: string,
    public readonly code: string,
    public readonly userId?: number,
  ) {
    super(message);
    this.name = 'DashboardStatsError';
  }
}

export class InvalidUserIdError extends DashboardStatsError {
  constructor(userId: number) {
    super(`Invalid user ID: ${userId}`, 'INVALID_USER_ID', userId);
  }
}

export class DatabaseQueryError extends DashboardStatsError {
  constructor(message: string, userId?: number) {
    super(`Database query failed: ${message}`, 'DATABASE_QUERY_ERROR', userId);
  }
}

export interface TokenIssuanceHour {
  hour: string;
  count: number;
}

export interface TokenIssuanceDay {
  date: string;
  count: number;
}

export interface ClientUsageStat {
  clientName: string;
  tokenCount: number;
  percentage: number;
}

export interface ScopeUsageStat {
  scope: string;
  count: number;
  percentage: number;
}

@Injectable()
export class DashboardStatsService {
  private readonly logger = new Logger(DashboardStatsService.name);

  constructor(
    @InjectRepository(Client)
    private clientRepository: Repository<Client>,
    @InjectRepository(User)
    private userRepository: Repository<User>,
    @InjectRepository(Token)
    private tokenRepository: Repository<Token>,
    private tokenService: TokenService,
    private cacheManagerService: CacheManagerService,
  ) {}

  /**
   * 타입 안전성을 위한 숫자 파싱 헬퍼 메서드
   */
  private safeParseInt(
    value: string | number | undefined | null,
    defaultValue: number = 0,
  ): number {
    if (value === null || value === undefined) return defaultValue;
    if (typeof value === 'number')
      return isNaN(value) ? defaultValue : Math.floor(value);
    const parsed = parseInt(value.toString(), 10);
    return isNaN(parsed) ? defaultValue : parsed;
  }

  /**
   * 토큰 발급 통계 헬퍼 메서드 (시간별/일별 공통 로직)
   */
  private async getTokenIssuanceStats<T>(
    userId: number,
    dateFormat: string,
    periods: number,
    periodMapper: (index: number) => string,
  ): Promise<T[]> {
    // 사용자 ID 검증
    if (!userId || userId <= 0) {
      throw new InvalidUserIdError(userId);
    }

    try {
      // 기간 계산
      const startDate = new Date();
      if (dateFormat.includes('%H')) {
        // 시간별: 24시간 전
        startDate.setHours(
          startDate.getHours() -
            DASHBOARD_CONFIG.STATS.TIME_RANGES.TOKEN_ISSUANCE_HOURS,
        );
      } else {
        // 일별: 30일 전
        startDate.setDate(
          startDate.getDate() -
            DASHBOARD_CONFIG.STATS.TIME_RANGES.TOKEN_ISSUANCE_DAYS,
        );
      }

      // 토큰 데이터 조회
      const tokens: Array<{ period: string; count: string | number }> =
        await this.tokenRepository
          .createQueryBuilder('token')
          .select(`DATE_FORMAT(token.createdAt, '${dateFormat}') as period`)
          .addSelect('COUNT(*) as count')
          .where('token.userId = :userId', { userId })
          .andWhere('token.tokenType = :tokenType', {
            tokenType: TOKEN_TYPES.OAUTH2,
          })
          .andWhere('token.createdAt >= :startDate', { startDate })
          .groupBy(`DATE_FORMAT(token.createdAt, '${dateFormat}')`)
          .orderBy(`DATE_FORMAT(token.createdAt, '${dateFormat}')`)
          .getRawMany();

      // 모든 기간을 채워서 결과 생성
      const result: T[] = [];
      for (let i = 0; i < periods; i++) {
        const period = periodMapper(i);
        const existing = tokens.find((t) => t.period === period);
        const count = existing?.count ? this.safeParseInt(existing.count) : 0;
        result.push({
          [dateFormat.includes('%H') ? 'hour' : 'date']: period,
          count,
        } as T);
      }

      return result;
    } catch (error) {
      this.logger.error('Error getting token issuance stats:', error);
      // 에러 발생 시 빈 결과 반환
      const result: T[] = [];
      for (let i = 0; i < periods; i++) {
        const period = periodMapper(i);
        result.push({
          [dateFormat.includes('%H') ? 'hour' : 'date']: period,
          count: 0,
        } as T);
      }
      return result;
    }
  }

  /**
   * 사용자 통계 캐시 무효화 (외부에서 호출 가능)
   */
  async invalidateUserStatsCache(userId: number): Promise<void> {
    return this.cacheManagerService.invalidateUserStatsCache(userId);
  }

  /**
   * 모든 사용자 캐시 무효화 (관리자용)
   */
  async invalidateAllUserCaches(): Promise<void> {
    return this.cacheManagerService.invalidateAllUsersCache();
  }

  async getTotalClientsCount(userId: number): Promise<number> {
    return await this.clientRepository.count({
      where: { isActive: true, userId },
    });
  }

  async getActiveTokensCount(userId: number): Promise<number> {
    return await this.tokenService.getActiveTokensCountForUser(userId);
  }

  async getTotalTokensIssuedCount(userId: number): Promise<number> {
    return await this.tokenRepository.count({
      where: {
        user: { id: userId },
        tokenType: TOKEN_TYPES.OAUTH2,
      },
    });
  }

  async getExpiredTokensCount(userId: number): Promise<number> {
    const now = new Date();
    return await this.tokenRepository.count({
      where: {
        user: { id: userId },
        expiresAt: LessThan(now),
        isRevoked: false,
        tokenType: TOKEN_TYPES.OAUTH2,
      },
    });
  }

  async getRevokedTokensCount(userId: number): Promise<number> {
    return await this.tokenRepository.count({
      where: {
        user: { id: userId },
        isRevoked: true,
        tokenType: TOKEN_TYPES.OAUTH2,
      },
    });
  }

  async getTokenIssuanceByHour(userId: number): Promise<TokenIssuanceHour[]> {
    return this.getTokenIssuanceStats<TokenIssuanceHour>(
      userId,
      '%H:00',
      DASHBOARD_CONFIG.STATS.TIME_RANGES.TOKEN_ISSUANCE_HOURS,
      (i) => `${i.toString().padStart(2, '0')}:00`,
    );
  }

  async getTokenIssuanceByDay(userId: number): Promise<TokenIssuanceDay[]> {
    return this.getTokenIssuanceStats<TokenIssuanceDay>(
      userId,
      '%Y-%m-%d',
      DASHBOARD_CONFIG.STATS.TIME_RANGES.TOKEN_ISSUANCE_DAYS,
      (i) => {
        const date = new Date();
        date.setDate(
          date.getDate() -
            (DASHBOARD_CONFIG.STATS.TIME_RANGES.TOKEN_ISSUANCE_DAYS - 1 - i),
        );
        return date.toISOString().split('T')[0];
      },
    );
  }

  async getClientUsageStats(userId: number): Promise<ClientUsageStat[]> {
    try {
      const totalTokens = await this.getTotalTokensIssuedCount(userId);

      if (totalTokens === 0) {
        return [];
      }

      const clientStats = await this.tokenRepository
        .createQueryBuilder('token')
        .select('client.name as clientName')
        .addSelect('COUNT(*) as tokenCount')
        .leftJoin('token.client', 'client')
        .where('token.userId = :userId', { userId })
        .andWhere('token.tokenType = :tokenType', {
          tokenType: TOKEN_TYPES.OAUTH2,
        })
        .groupBy('client.id')
        .orderBy('tokenCount', 'DESC')
        .limit(10)
        .getRawMany();

      return (clientStats as RawTokenStats[]).map((stat) => {
        const tokenCount = this.safeParseInt(stat.tokenCount);
        const percentage =
          totalTokens > 0
            ? Math.round((tokenCount / totalTokens) * 100 * 10) / 10
            : 0;

        return {
          clientName: stat.clientName || 'Unknown',
          tokenCount,
          percentage,
        };
      });
    } catch (error) {
      this.logger.error('Error getting client usage stats:', error);
      return [];
    }
  }

  async getScopeUsageStats(userId: number): Promise<ScopeUsageStat[]> {
    // 사용자 ID 검증
    if (!userId || userId <= 0) {
      throw new InvalidUserIdError(userId);
    }

    try {
      // 1. 총 토큰 수 계산 (스코프가 있는 토큰만)
      const totalTokensWithScopes = await this.tokenRepository.count({
        where: {
          user: { id: userId },
          tokenType: TOKEN_TYPES.OAUTH2,
        },
      });

      if (totalTokensWithScopes === 0) {
        return [];
      }

      // 2. 실제 데이터베이스에서 사용되는 스코프들을 동적으로 추출
      const scopeData = await this.tokenRepository
        .createQueryBuilder('token')
        .select('token.scopes', 'scopes')
        .where('token.userId = :userId', { userId })
        .andWhere('token.tokenType = :tokenType', {
          tokenType: TOKEN_TYPES.OAUTH2,
        })
        .andWhere('token.scopes IS NOT NULL')
        .andWhere('JSON_LENGTH(token.scopes) > 0')
        .getRawMany();

      // 3. 모든 스코프를 추출하고 집계
      const scopeCountMap = new Map<string, number>();

      for (const row of scopeData) {
        try {
          const scopesString = (row as { scopes: string }).scopes;
          if (typeof scopesString === 'string') {
            const scopes = JSON.parse(scopesString) as string[];
            if (Array.isArray(scopes)) {
              scopes.forEach((scope) => {
                if (typeof scope === 'string' && scope.trim()) {
                  const trimmedScope = scope.trim();
                  scopeCountMap.set(
                    trimmedScope,
                    (scopeCountMap.get(trimmedScope) || 0) + 1,
                  );
                }
              });
            }
          }
        } catch (error) {
          // JSON 파싱 실패 시 무시
          this.logger.warn(
            'Failed to parse scopes JSON:',
            (row as { scopes: string }).scopes,
            error,
          );
        }
      }

      // 4. 결과를 ScopeUsageStat[] 형태로 변환
      const scopeStats: ScopeUsageStat[] = Array.from(scopeCountMap.entries())
        .map(([scope, count]) => ({
          scope,
          count,
          percentage:
            Math.round((count / totalTokensWithScopes) * 100 * 10) / 10,
        }))
        .filter((stat) => stat.count > 0)
        .sort((a, b) => b.count - a.count)
        .slice(0, DASHBOARD_CONFIG.STATS.LIMITS.SCOPE_USAGE_TOP);

      return scopeStats;
    } catch (error) {
      this.logger.error('Error getting scope usage stats:', error);

      // 폴백: 기본 스코프 목록으로 제한된 통계 제공
      try {
        return await this.getScopeUsageStatsFallback(userId);
      } catch (fallbackError) {
        this.logger.error('Fallback scope stats also failed:', fallbackError);
        return [];
      }
    }
  }

  /**
   * 스코프 통계 폴백 메서드 (기본 스코프만 분석)
   */
  private async getScopeUsageStatsFallback(
    userId: number,
  ): Promise<ScopeUsageStat[]> {
    const totalTokens = await this.tokenRepository.count({
      where: {
        user: { id: userId },
        tokenType: TOKEN_TYPES.OAUTH2,
      },
    });

    if (totalTokens === 0) {
      return [];
    }

    // 기본 스코프 목록만 분석 (단일 쿼리로 배치 처리)
    const scopePromises = DASHBOARD_CONFIG.STATS.DEFAULT_SCOPES.map(
      async (scope) => {
        try {
          const count = await this.tokenRepository
            .createQueryBuilder('token')
            .where('token.userId = :userId', { userId })
            .andWhere('token.tokenType = :tokenType', {
              tokenType: TOKEN_TYPES.OAUTH2,
            })
            .andWhere('JSON_CONTAINS(token.scopes, :scope)', {
              scope: JSON.stringify(scope),
            })
            .getCount();

          return {
            scope,
            count,
            percentage:
              totalTokens > 0
                ? Math.round((count / totalTokens) * 100 * 10) / 10
                : 0,
          };
        } catch (error) {
          this.logger.warn(`Error counting scope '${scope}':`, error);
          return {
            scope,
            count: 0,
            percentage: 0,
          };
        }
      },
    );

    const scopeStats = await Promise.all(scopePromises);
    return scopeStats
      .filter((stat) => stat.count > 0)
      .sort((a, b) => b.count - a.count);
  }

  async getAverageTokenLifetime(userId: number): Promise<number> {
    const tokens = await this.tokenRepository.find({
      where: {
        user: { id: userId },
        tokenType: TOKEN_TYPES.OAUTH2,
      },
      select: ['createdAt', 'expiresAt'],
    });

    if (tokens.length === 0) {
      return 0;
    }

    const lifetimes = tokens
      .filter((token) => token.expiresAt)
      .map((token) => {
        const diffMs = token.expiresAt.getTime() - token.createdAt.getTime();
        return diffMs / (1000 * 60 * 60); // 시간 단위로 변환
      });

    if (lifetimes.length === 0) {
      return 0;
    }

    const average =
      lifetimes.reduce((sum, lifetime) => sum + lifetime, 0) / lifetimes.length;
    return Math.round(average * 10) / 10;
  }
}
