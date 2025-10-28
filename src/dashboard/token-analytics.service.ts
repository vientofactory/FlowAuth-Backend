import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, MoreThan } from 'typeorm';
import { Token } from '../oauth2/token.entity';
import { Client } from '../oauth2/client.entity';
import { User } from '../auth/user.entity';
import { AuditLog, AuditEventType } from '../common/audit-log.entity';
import { TOKEN_TYPES } from '../constants/auth.constants';

interface HourlyPattern {
  hour: number;
  totalTokens: number;
  avgLifetime: number;
}

interface DailyPattern {
  dayOfWeek: number;
  totalTokens: number;
  avgLifetime: number;
}

interface RawHourlyPattern {
  hour: string | number;
  totalTokens: string | number;
  avgLifetime: string | number;
}

interface RawDailyPattern {
  dayOfWeek: string | number;
  totalTokens: string | number;
  avgLifetime: string | number;
}

export interface TokenUsagePattern {
  hour: number;
  dayOfWeek: number;
  averageUsage: number;
  peakUsage: number;
  totalTokens: number;
}

export interface ClientPerformanceMetrics {
  clientId: string;
  clientName: string;
  totalTokens: number;
  activeTokens: number;
  expiredTokens: number;
  revokedTokens: number;
  averageTokenLifetime: number;
  tokenSuccessRate: number; // (total - revoked) / total
  lastActivity: Date;
}

export interface UserActivityMetrics {
  userId: number;
  username: string;
  totalTokens: number;
  activeTokens: number;
  loginCount: number;
  lastLogin: Date;
  averageSessionDuration: number;
  preferredScopes: string[];
  riskScore: number; // 0-100, higher means higher risk
}

@Injectable()
export class TokenAnalyticsService {
  private readonly logger = new Logger(TokenAnalyticsService.name);

  constructor(
    @InjectRepository(Token)
    private tokenRepository: Repository<Token>,
    @InjectRepository(Client)
    private clientRepository: Repository<Client>,
    @InjectRepository(User)
    private userRepository: Repository<User>,
    @InjectRepository(AuditLog)
    private auditLogRepository: Repository<AuditLog>,
  ) {}

  /**
   * 토큰 사용 패턴 분석 (시간별/요일별)
   */
  async getTokenUsagePatterns(
    userId: number,
    days: number = 30,
  ): Promise<TokenUsagePattern[]> {
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - days);

    try {
      // 시간별 사용 패턴
      const rawHourlyPatterns = await this.tokenRepository
        .createQueryBuilder('token')
        .select('HOUR(token.createdAt) as hour')
        .addSelect('COUNT(*) as totalTokens')
        .addSelect(
          'AVG(TIMESTAMPDIFF(HOUR, token.createdAt, token.expiresAt)) as avgLifetime',
        )
        .where('token.userId = :userId', { userId })
        .andWhere('token.createdAt >= :startDate', { startDate })
        .andWhere('token.tokenType = :tokenType', {
          tokenType: TOKEN_TYPES.OAUTH2,
        })
        .groupBy('HOUR(token.createdAt)')
        .orderBy('hour')
        .getRawMany();

      const hourlyPatterns: HourlyPattern[] = rawHourlyPatterns.map(
        (row: RawHourlyPattern) => ({
          hour: Number(row.hour),
          totalTokens: Number(row.totalTokens),
          avgLifetime: Number(row.avgLifetime),
        }),
      );

      // 요일별 사용 패턴
      const rawDailyPatterns = await this.tokenRepository
        .createQueryBuilder('token')
        .select('WEEKDAY(token.createdAt) as dayOfWeek')
        .addSelect('COUNT(*) as totalTokens')
        .addSelect(
          'AVG(TIMESTAMPDIFF(HOUR, token.createdAt, token.expiresAt)) as avgLifetime',
        )
        .where('token.userId = :userId', { userId })
        .andWhere('token.createdAt >= :startDate', { startDate })
        .andWhere('token.tokenType = :tokenType', {
          tokenType: TOKEN_TYPES.OAUTH2,
        })
        .groupBy('WEEKDAY(token.createdAt)')
        .orderBy('dayOfWeek')
        .getRawMany();

      const dailyPatterns: DailyPattern[] = rawDailyPatterns.map(
        (row: RawDailyPattern) => ({
          dayOfWeek: Number(row.dayOfWeek),
          totalTokens: Number(row.totalTokens),
          avgLifetime: Number(row.avgLifetime),
        }),
      );

      // 결과를 결합
      const patterns: TokenUsagePattern[] = [];

      for (let hour = 0; hour < 24; hour++) {
        for (let day = 0; day < 7; day++) {
          const hourlyData = hourlyPatterns.find((h) => h.hour === hour);
          const dailyData = dailyPatterns.find((d) => d.dayOfWeek === day);

          if (hourlyData || dailyData) {
            patterns.push({
              hour,
              dayOfWeek: day,
              averageUsage: hourlyData?.avgLifetime ?? 0,
              peakUsage: Math.max(
                hourlyData?.totalTokens ?? 0,
                dailyData?.totalTokens ?? 0,
              ),
              totalTokens:
                (hourlyData?.totalTokens ?? 0) + (dailyData?.totalTokens ?? 0),
            });
          }
        }
      }

      return patterns;
    } catch (error) {
      this.logger.error('Error getting token usage patterns:', error);
      return [];
    }
  }

  /**
   * 클라이언트별 성능 메트릭스
   */
  async getClientPerformanceMetrics(
    userId: number,
  ): Promise<ClientPerformanceMetrics[]> {
    try {
      const clients = await this.clientRepository.find({
        where: { userId },
        select: ['id', 'name'],
      });

      const metrics: ClientPerformanceMetrics[] = [];

      for (const client of clients) {
        const tokens = await this.tokenRepository.find({
          where: { client: { id: client.id } },
          select: ['id', 'createdAt', 'expiresAt', 'isRevoked'],
        });

        const now = new Date();
        const totalTokens = tokens.length;
        const activeTokens = tokens.filter(
          (t) => !t.isRevoked && t.expiresAt > now,
        ).length;
        const expiredTokens = tokens.filter(
          (t) => t.expiresAt <= now && !t.isRevoked,
        ).length;
        const revokedTokens = tokens.filter((t) => t.isRevoked).length;

        // 평균 토큰 수명 계산
        const lifetimes = tokens
          .filter((t) => t.expiresAt)
          .map((t) => t.expiresAt.getTime() - t.createdAt.getTime());
        const averageTokenLifetime =
          lifetimes.length > 0
            ? lifetimes.reduce((sum, life) => sum + life, 0) /
              lifetimes.length /
              (1000 * 60 * 60) // 시간 단위
            : 0;

        // 토큰 성공률 계산
        const tokenSuccessRate =
          totalTokens > 0
            ? ((totalTokens - revokedTokens) / totalTokens) * 100
            : 0;

        // 마지막 활동
        const lastActivity =
          tokens.length > 0
            ? new Date(Math.max(...tokens.map((t) => t.createdAt.getTime())))
            : new Date();

        metrics.push({
          clientId: client.clientId,
          clientName: client.name,
          totalTokens,
          activeTokens,
          expiredTokens,
          revokedTokens,
          averageTokenLifetime: Math.round(averageTokenLifetime * 10) / 10,
          tokenSuccessRate: Math.round(tokenSuccessRate * 10) / 10,
          lastActivity,
        });
      }

      return metrics.sort((a, b) => b.totalTokens - a.totalTokens);
    } catch (error) {
      this.logger.error('Error getting client performance metrics:', error);
      return [];
    }
  }

  /**
   * 사용자 활동 메트릭스
   */
  async getUserActivityMetrics(userId: number): Promise<UserActivityMetrics> {
    try {
      const user = await this.userRepository.findOne({
        where: { id: userId },
        select: ['id', 'username', 'lastLoginAt'],
      });

      if (!user) {
        throw new Error(`User with id ${userId} not found`);
      }

      // 토큰 통계
      const tokens = await this.tokenRepository.find({
        where: { user: { id: userId } },
        select: ['id', 'createdAt', 'expiresAt', 'isRevoked', 'scopes'],
      });

      const now = new Date();
      const totalTokens = tokens.length;
      const activeTokens = tokens.filter(
        (t) => !t.isRevoked && t.expiresAt > now,
      ).length;

      // 로그인 횟수 (감사 로그에서 조회)
      const loginCount = await this.auditLogRepository.count({
        where: {
          userId,
          eventType: AuditEventType.USER_LOGIN,
          createdAt: MoreThan(new Date(Date.now() - 30 * 24 * 60 * 60 * 1000)), // 30일
        },
      });

      // 선호 스코프 분석
      const scopeCount = new Map<string, number>();
      tokens.forEach((token) => {
        if (token.scopes) {
          token.scopes.forEach((scope) => {
            scopeCount.set(scope, (scopeCount.get(scope) ?? 0) + 1);
          });
        }
      });

      const preferredScopes = Array.from(scopeCount.entries())
        .sort(([, a], [, b]) => b - a)
        .slice(0, 5)
        .map(([scope]) => scope);

      // 위험 점수 계산 (실패한 인증 시도 기반)
      const failedAttempts = await this.auditLogRepository.count({
        where: {
          userId,
          eventType: AuditEventType.FAILED_AUTH_ATTEMPT,
          createdAt: MoreThan(new Date(Date.now() - 7 * 24 * 60 * 60 * 1000)), // 7일
        },
      });

      const riskScore = Math.min(
        (failedAttempts / Math.max(loginCount, 1)) * 50 +
          (tokens.filter((t) => t.isRevoked).length /
            Math.max(totalTokens, 1)) *
            50,
        100,
      );

      return {
        userId,
        username: user.username,
        totalTokens,
        activeTokens,
        loginCount,
        lastLogin: user.lastLoginAt ?? new Date(),
        averageSessionDuration: 0, // TODO: 세션 지속 시간 계산 로직 추가
        preferredScopes,
        riskScore: Math.round(riskScore),
      };
    } catch (error) {
      this.logger.error('Error getting user activity metrics:', error);
      throw error;
    }
  }
}
