import { Injectable, Inject, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import type { Cache } from 'cache-manager';
import { Client } from '../oauth2/client.entity';
import { User } from '../auth/user.entity';
import { Token } from '../oauth2/token.entity';
import { TokenService } from '../oauth2/token.service';
import { DashboardStatsService } from './dashboard-stats.service';
import { DashboardAnalyticsService } from './dashboard-analytics.service';
import { DashboardStatsResponseDto } from './dto/dashboard-stats.dto';
import { RecentActivityDto } from './dto/recent-activity.dto';
import {
  ConnectedAppDto,
  ConnectedAppsResponseDto,
  RevokeConnectionResponseDto,
} from './dto/connected-apps.dto';
import { CacheManagerService } from './cache-manager.service';
import { DASHBOARD_CONFIG, CACHE_KEYS } from './dashboard.constants';

@Injectable()
export class DashboardService {
  private readonly logger = new Logger(DashboardService.name);

  constructor(
    @InjectRepository(Client)
    private clientRepository: Repository<Client>,
    @InjectRepository(User)
    private userRepository: Repository<User>,
    @InjectRepository(Token)
    private tokenRepository: Repository<Token>,
    private tokenService: TokenService,
    private dashboardStatsService: DashboardStatsService,
    private dashboardAnalyticsService: DashboardAnalyticsService,
    private cacheManagerService: CacheManagerService,
    @Inject(CACHE_MANAGER)
    private cacheManager: Cache,
  ) {}

  async getDashboardStats(userId: number): Promise<DashboardStatsResponseDto> {
    const cacheKey = CACHE_KEYS.stats(userId);

    try {
      // 캐시에서 먼저 조회
      const cached =
        await this.cacheManager.get<DashboardStatsResponseDto>(cacheKey);
      if (cached) {
        return cached;
      }

      // 캐시에 없으면 DB 조회 - 통계 서비스 사용
      const [
        totalClients,
        activeTokens,
        totalTokensIssued,
        expiredTokens,
        revokedTokens,
        tokenIssuanceByHour,
        tokenIssuanceByDay,
        clientUsageStats,
        scopeUsageStats,
        averageTokenLifetime,
      ] = await Promise.all([
        this.dashboardStatsService.getTotalClientsCount(userId),
        this.dashboardStatsService.getActiveTokensCount(userId),
        this.dashboardStatsService.getTotalTokensIssuedCount(userId),
        this.dashboardStatsService.getExpiredTokensCount(userId),
        this.dashboardStatsService.getRevokedTokensCount(userId),
        this.dashboardStatsService.getTokenIssuanceByHour(userId),
        this.dashboardStatsService.getTokenIssuanceByDay(userId),
        this.dashboardStatsService.getClientUsageStats(userId),
        this.dashboardStatsService.getScopeUsageStats(userId),
        this.dashboardStatsService.getAverageTokenLifetime(userId),
      ]);

      const user = await this.userRepository.findOne({
        where: { id: userId },
        select: ['createdAt', 'lastLoginAt'],
      });

      // 토큰 만료율 계산
      const tokenExpirationRate =
        totalTokensIssued > 0 ? (expiredTokens / totalTokensIssued) * 100 : 0;

      // 인사이트 분석 - 분석 서비스 사용
      const insights = this.dashboardAnalyticsService.generateInsights({
        totalClients,
        activeTokens,
        totalTokensIssued,
        expiredTokens,
        revokedTokens,
        tokenIssuanceByDay,
        tokenExpirationRate,
        averageTokenLifetime,
      });

      const result = {
        totalClients,
        activeTokens,
        totalTokensIssued,
        expiredTokens,
        revokedTokens,
        lastLoginDate: user?.lastLoginAt || null,
        accountCreated: user?.createdAt || null,
        tokenIssuanceByHour,
        tokenIssuanceByDay,
        clientUsageStats,
        scopeUsageStats,
        tokenExpirationRate,
        averageTokenLifetime,
        insights,
      };

      // 결과를 캐시에 저장
      await this.cacheManager.set(cacheKey, result, DASHBOARD_CONFIG.CACHE.TTL);
      return result;
    } catch (error) {
      this.logger.error('Failed to get dashboard stats:', error);
      // 에러 발생 시 기본값 반환
      return {
        totalClients: 0,
        activeTokens: 0,
        totalTokensIssued: 0,
        expiredTokens: 0,
        revokedTokens: 0,
        lastLoginDate: null,
        accountCreated: null,
        tokenIssuanceByHour: [],
        tokenIssuanceByDay: [],
        clientUsageStats: [],
        scopeUsageStats: [],
        tokenExpirationRate: 0,
        averageTokenLifetime: 0,
        insights: {
          trends: '통계 데이터를 불러올 수 없습니다.',
          recommendations: '시스템 관리자에게 문의하세요.',
          alerts: '데이터 조회 중 오류가 발생했습니다.',
        },
      };
    }
  }

  async getRecentActivities(
    userId: number,
    limit: number = 10,
  ): Promise<RecentActivityDto[]> {
    const cacheKey = CACHE_KEYS.activities(userId, limit);

    try {
      // 캐시에서 먼저 조회
      const cached = await this.cacheManager.get<RecentActivityDto[]>(cacheKey);
      if (cached) {
        return cached;
      }

      const activities: RecentActivityDto[] = [];
      let activityCounter = 1;

      // 1. 사용자 로그인 활동
      const user = await this.userRepository.findOne({
        where: { id: userId },
        select: ['lastLoginAt'],
      });

      if (user?.lastLoginAt) {
        activities.push({
          id: activityCounter++,
          type: 'login',
          description: '사용자 로그인',
          createdAt: user.lastLoginAt,
          metadata: {
            userId,
            activity: '사용자가 시스템에 로그인했습니다.',
            location: '웹 애플리케이션',
          },
        });
      }

      // 1.5. 계정 생성 활동 (한 번만 표시)
      const accountUser = await this.userRepository.findOne({
        where: { id: userId },
        select: ['createdAt'],
      });

      if (accountUser?.createdAt) {
        activities.push({
          id: activityCounter++,
          type: 'account_created',
          description: '계정 생성됨',
          createdAt: accountUser.createdAt,
          metadata: {
            userId,
            activity: '새로운 사용자 계정이 생성되었습니다.',
            details: {
              createdAt: accountUser.createdAt,
            },
          },
        });
      }

      // 2. 클라이언트 생성/수정 활동
      const recentClients = await this.clientRepository.find({
        where: { userId },
        select: [
          'id',
          'name',
          'createdAt',
          'updatedAt',
          'isActive',
          'isConfidential',
          'description',
        ],
        order: { updatedAt: 'DESC' },
        take: 5,
      });

      recentClients.forEach((client) => {
        // 생성 활동
        activities.push({
          id: activityCounter++,
          type: 'client_created',
          description: `클라이언트 "${client.name}" 생성됨`,
          createdAt: client.createdAt,
          resourceId: client.id,
          metadata: {
            clientName: client.name,
            clientId: client.id,
            activity: `새 OAuth2 클라이언트가 생성되었습니다.`,
            details: {
              isActive: client.isActive,
              isConfidential: client.isConfidential,
              description: client.description,
              createdAt: client.createdAt,
            },
          },
        });

        // 수정 활동 (생성일과 수정일이 다른 경우)
        if (client.updatedAt.getTime() !== client.createdAt.getTime()) {
          activities.push({
            id: activityCounter++,
            type: 'client_updated',
            description: `클라이언트 "${client.name}" 정보 수정됨`,
            createdAt: client.updatedAt,
            resourceId: client.id,
            metadata: {
              clientName: client.name,
              clientId: client.id,
              activity: `OAuth2 클라이언트 정보가 수정되었습니다.`,
              details: {
                isActive: client.isActive,
                isConfidential: client.isConfidential,
                updatedAt: client.updatedAt,
              },
            },
          });
        }
      });

      // 3. 토큰 생성/취소 활동
      const recentTokens = await this.tokenRepository.find({
        where: { user: { id: userId } },
        relations: ['client'],
        select: [
          'id',
          'createdAt',
          'isRevoked',
          'revokedAt',
          'scopes',
          'expiresAt',
        ],
        order: { createdAt: 'DESC' },
        take: 5,
      });

      recentTokens.forEach((token) => {
        // 토큰 생성 활동
        activities.push({
          id: activityCounter++,
          type: 'token_created',
          description: `"${token.client?.name || '웹 애플리케이션'}" 토큰 발급됨`,
          createdAt: token.createdAt,
          resourceId: token.id,
          metadata: {
            clientName: token.client?.name,
            clientId: token.client?.id,
            activity: `새로운 액세스 토큰이 발급되었습니다.`,
            details: {
              scopes: token.scopes,
              expiresAt: token.expiresAt,
              tokenId: token.id,
            },
          },
        });

        // 토큰 취소 활동
        if (token.isRevoked) {
          activities.push({
            id: activityCounter++,
            type: 'token_revoked',
            description: `"${token.client?.name || '웹 애플리케이션'}" 토큰 취소됨`,
            createdAt: token.revokedAt || new Date(), // 취소 시간이 없으면 현재 시간 사용
            resourceId: token.id,
            metadata: {
              clientName: token.client?.name,
              clientId: token.client?.id,
              activity: `액세스 토큰이 취소되었습니다.`,
              reason: '관리자 취소',
              details: {
                scopes: token.scopes,
                tokenId: token.id,
              },
            },
          });
        }
      });

      // 시간순으로 정렬 (최신순)
      activities.sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());

      // 제한된 개수만큼 반환
      const result = activities.slice(0, limit);

      // 결과를 캐시에 저장 (2분 TTL)
      await this.cacheManager.set(cacheKey, result, 120000);
      return result;
    } catch (error) {
      this.logger.error('Failed to get recent activities:', error);
      // 에러 발생 시 빈 배열 반환
      return [];
    }
  }

  async getConnectedApps(userId: number): Promise<ConnectedAppsResponseDto> {
    // 사용자가 토큰을 발급받은 클라이언트들을 조회
    const tokens = await this.tokenRepository.find({
      where: {
        user: { id: userId },
        isRevoked: false,
      },
      relations: ['client'],
      select: ['id', 'client', 'scopes', 'createdAt', 'expiresAt'],
      order: { createdAt: 'DESC' },
    });

    // 클라이언트별로 최신 토큰 정보를 그룹화
    const clientMap = new Map<number, ConnectedAppDto>();

    tokens.forEach((token) => {
      if (!token.client) return;

      const clientId = token.client.id;
      const existingApp = clientMap.get(clientId);

      if (!existingApp || token.createdAt > existingApp.connectedAt) {
        const status = token.isRevoked
          ? 'revoked'
          : new Date() > token.expiresAt
            ? 'expired'
            : 'active';

        clientMap.set(clientId, {
          id: clientId,
          name: token.client.name,
          description: token.client.description,
          logoUrl: token.client.logoUri,
          scopes: token.scopes || [],
          connectedAt: token.createdAt,
          lastUsedAt: undefined, // Token 엔티티에 lastUsedAt 필드가 없음
          expiresAt: token.expiresAt,
          status,
        });
      }
    });

    const apps = Array.from(clientMap.values());

    return {
      apps,
      total: apps.length,
    };
  }

  /**
   * 사용자 통계 캐시 무효화 (외부에서 호출 가능)
   */
  async invalidateUserStatsCache(userId: number): Promise<void> {
    return this.cacheManagerService.invalidateUserStatsCache(userId);
  }

  /**
   * 사용자 활동 캐시 무효화 (외부에서 호출 가능)
   */
  async invalidateUserActivitiesCache(userId: number): Promise<void> {
    return this.cacheManagerService.invalidateUserActivitiesCache(userId);
  }

  /**
   * 모든 사용자 캐시 무효화 (관리자용)
   */
  async invalidateAllUserCaches(): Promise<void> {
    return this.cacheManagerService.invalidateAllUsersCache();
  }

  async revokeConnection(
    userId: number,
    clientId: number,
  ): Promise<RevokeConnectionResponseDto> {
    // 해당 사용자의 해당 클라이언트에 대한 모든 토큰을 취소
    const result = await this.tokenRepository.update(
      {
        user: { id: userId },
        client: { id: clientId },
        isRevoked: false,
      },
      {
        isRevoked: true,
      },
    );

    return {
      success: true,
      revokedTokensCount: result.affected || 0,
      message: '연결이 성공적으로 해제되었습니다.',
    };
  }
}
