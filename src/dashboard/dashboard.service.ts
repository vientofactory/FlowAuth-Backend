import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Client } from '../oauth2/client.entity';
import { User } from '../auth/user.entity';
import { Token } from '../oauth2/token.entity';
import { DashboardStatsService } from './dashboard-stats.service';
import { DashboardAnalyticsService } from './dashboard-analytics.service';
import { DashboardStatsResponseDto } from './dto/dashboard-stats.dto';
import { RecentActivityDto } from './dto/recent-activity.dto';
import {
  ConnectedAppDto,
  ConnectedAppsResponseDto,
  RevokeConnectionResponseDto,
} from './dto/connected-apps.dto';
import { CacheManagerService } from '../cache/cache-manager.service';
import { AuditLogService } from '../common/audit-log.service';
import {
  AuditEventType,
  AuditSeverity,
  AuditLog,
} from '../common/audit-log.entity';
import { TokenAnalyticsService } from './token-analytics.service';
import { SecurityMetricsService } from './security-metrics.service';
import { CACHE_CONFIG } from '../constants/cache.constants';
import { CACHE_KEYS } from './dashboard.constants';
import { StatisticsRecordingService } from './statistics-recording.service';
import { DASHBOARD_CONFIG } from './dashboard.constants';
import {
  TOKEN_REVOCATION_REASONS,
  AUDIT_LOG_RESOURCE_TYPES,
  ACTIVITY_TYPES,
  TOKEN_REVOCATION_REASON_DESCRIPTIONS,
} from '../constants/oauth2.constants';

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
    private dashboardStatsService: DashboardStatsService,
    private dashboardAnalyticsService: DashboardAnalyticsService,
    private cacheManagerService: CacheManagerService,
    private auditLogService: AuditLogService,
    private tokenAnalyticsService: TokenAnalyticsService,
    private securityMetricsService: SecurityMetricsService,
    private statisticsRecordingService: StatisticsRecordingService,
  ) {}

  async getDashboardStats(userId: number): Promise<DashboardStatsResponseDto> {
    const cacheKey = CACHE_KEYS.dashboard.stats(userId);

    try {
      // Use cache first
      const cached =
        await this.cacheManagerService.getCacheValue<DashboardStatsResponseDto>(
          cacheKey,
        );
      if (cached) {
        return cached;
      }

      // Use database to get stats
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

      // Calculate token expiration rate
      const tokenExpirationRate =
        totalTokensIssued > 0 ? (expiredTokens / totalTokensIssued) * 100 : 0;

      // Create insights using analytics service
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
        lastLoginDate: user?.lastLoginAt ?? null,
        accountCreated: user?.createdAt ?? null,
        tokenIssuanceByHour,
        tokenIssuanceByDay,
        clientUsageStats,
        scopeUsageStats,
        tokenExpirationRate,
        averageTokenLifetime,
        insights,
      };

      // Save to cache
      await this.cacheManagerService.setCacheValue(
        cacheKey,
        result,
        CACHE_CONFIG.TTL.DASHBOARD_STATS,
      );
      return result;
    } catch (error) {
      this.logger.error('Failed to get dashboard stats:', error);
      // Default empty stats on error
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
    offset: number = 0,
  ): Promise<{ activities: RecentActivityDto[]; total: number }> {
    let sanitizedLimit = Number(limit) || 10;
    sanitizedLimit = Math.max(1, Math.floor(sanitizedLimit));
    const configuredMax = DASHBOARD_CONFIG.ACTIVITIES.MAX_LIMIT;

    if (sanitizedLimit > configuredMax) {
      sanitizedLimit = configuredMax;
    }

    limit = sanitizedLimit;

    const cacheKey = CACHE_KEYS.dashboard.activities(userId);

    try {
      // Use cache first
      const cached = await this.cacheManagerService.getCacheValue<{
        activities: RecentActivityDto[];
        total: number;
      }>(cacheKey);
      if (cached) {
        // Apply pagination to cached data
        const resultActivities = cached.activities.slice(
          offset,
          offset + limit,
        );
        return { activities: resultActivities, total: cached.total };
      }

      // Get activity data from audit logs
      const [auditLogs] = await this.auditLogService.getUserAuditLogs(userId, {
        limit: 1000, // Get enough data
        offset: 0,
        eventTypes: [
          AuditEventType.USER_LOGIN,
          AuditEventType.TOKEN_ISSUED,
          AuditEventType.TOKEN_REVOKED,
          AuditEventType.CLIENT_CREATED,
          AuditEventType.CLIENT_UPDATED,
          AuditEventType.CLIENT_DELETED,
        ],
      });

      // Get user information
      const user = await this.userRepository.findOne({
        where: { id: userId },
        select: ['username', 'email'],
      });

      // FAILED_AUTH_ATTEMPT Events
      let failedAuthLogs: AuditLog[] = [];
      if (user?.email) {
        const [failedLogs] =
          await this.auditLogService.getFailedAuthAttemptsByEmail(user.email, {
            limit: 1000, // Get enough data
            offset: 0,
          });
        failedAuthLogs = failedLogs;
      }

      // Merge results
      const allAuditLogs = [...auditLogs, ...failedAuthLogs];

      // Convert audit logs to activity DTOs
      const allActivities: RecentActivityDto[] = allAuditLogs.map((log) => {
        // Map cancellation reasons to user-friendly descriptions
        const mappedMetadata = { ...log.metadata };
        if (
          mappedMetadata.reason &&
          typeof mappedMetadata.reason === 'string'
        ) {
          mappedMetadata.reason =
            TOKEN_REVOCATION_REASON_DESCRIPTIONS[
              mappedMetadata.reason as keyof typeof TOKEN_REVOCATION_REASON_DESCRIPTIONS
            ] || mappedMetadata.reason;
        }

        return {
          id: log.id,
          type: this.mapAuditEventTypeToActivityType(log.eventType),
          description: log.description,
          createdAt: log.createdAt,
          resourceId: log.resourceId ?? undefined,
          metadata: {
            ...mappedMetadata,
            ipAddress: log.ipAddress,
            userAgent: log.userAgent,
            severity: log.severity,
          },
        };
      });

      // Add default activities for compatibility with existing logic (when not in audit logs)
      if (allActivities.length < limit + offset) {
        await this.addLegacyActivities(
          userId,
          allActivities,
          limit + offset - allActivities.length,
        );
      }

      // Sort by time (newest first)
      allActivities.sort(
        (a, b) => b.createdAt.getTime() - a.createdAt.getTime(),
      );

      // Apply offset and limit
      const resultActivities = allActivities.slice(offset, offset + limit);
      const total = allActivities.length;

      const result = { activities: resultActivities, total };

      // Cache the full activities data for efficient pagination
      const fullCacheData = { activities: allActivities, total };
      await this.cacheManagerService.setCacheValue(
        cacheKey,
        fullCacheData,
        CACHE_CONFIG.TTL.DASHBOARD_ACTIVITIES,
      );

      return result;
    } catch (error) {
      this.logger.error('Failed to get recent activities:', error);
      // Fallback to legacy method on error
      const legacyActivities = await this.getRecentActivitiesLegacy(
        userId,
        limit,
      );
      return { activities: legacyActivities, total: legacyActivities.length };
    }
  }

  /**
   * Map audit log event types to activity types
   */
  private mapAuditEventTypeToActivityType(
    eventType: AuditEventType,
  ): RecentActivityDto['type'] {
    switch (eventType) {
      case AuditEventType.USER_LOGIN:
        return 'login';
      case AuditEventType.TOKEN_ISSUED:
        return 'token_created';
      case AuditEventType.TOKEN_REVOKED:
        return 'token_revoked';
      case AuditEventType.CLIENT_CREATED:
        return 'client_created';
      case AuditEventType.CLIENT_UPDATED:
        return 'client_updated';
      case AuditEventType.CLIENT_DELETED:
        return 'client_deleted';
      case AuditEventType.FAILED_AUTH_ATTEMPT:
        return 'login_failed';
      default:
        return 'login'; // Return login as default
    }
  }

  /**
   * Add legacy activities when audit logs are insufficient
   */
  private async addLegacyActivities(
    userId: number,
    activities: RecentActivityDto[],
    remainingCount: number,
  ): Promise<void> {
    const existingIds = new Set(activities.map((a) => a.id));

    // Add account creation activity (if not present)
    const accountUser = await this.userRepository.findOne({
      where: { id: userId },
      select: ['createdAt'],
    });

    if (
      accountUser?.createdAt &&
      !activities.some((a) => a.type === ACTIVITY_TYPES.ACCOUNT_CREATED)
    ) {
      const newId = Math.max(...existingIds, 0) + 1;
      activities.push({
        id: newId,
        type: ACTIVITY_TYPES.ACCOUNT_CREATED,
        description: 'Account created',
        createdAt: accountUser.createdAt,
        metadata: {
          userId,
          activity: 'New user account has been created.',
          details: {
            createdAt: accountUser.createdAt,
          },
        },
      });
      existingIds.add(newId);
      if (activities.length >= remainingCount) return;
    }
  }

  /**
   * Retrieve activities using legacy method (for fallback)
   */
  private async getRecentActivitiesLegacy(
    userId: number,
    limit: number = 10,
  ): Promise<RecentActivityDto[]> {
    try {
      const activities: RecentActivityDto[] = [];
      let activityCounter = 1;

      // 1. User login activities
      const user = await this.userRepository.findOne({
        where: { id: userId },
        select: ['lastLoginAt'],
      });

      if (user?.lastLoginAt) {
        activities.push({
          id: activityCounter++,
          type: ACTIVITY_TYPES.LOGIN,
          description: 'User login',
          createdAt: user.lastLoginAt,
          metadata: {
            userId,
            activity: 'User logged into the system.',
            location: 'Web application',
          },
        });
      }

      // 1.5. Account creation activity
      const accountUser = await this.userRepository.findOne({
        where: { id: userId },
        select: ['createdAt'],
      });

      if (accountUser?.createdAt) {
        activities.push({
          id: activityCounter++,
          type: 'account_created',
          description: 'Account created',
          createdAt: accountUser.createdAt,
          metadata: {
            userId,
            activity: 'New user account has been created.',
            details: {
              createdAt: accountUser.createdAt,
            },
          },
        });
      }

      // 2. Client creation/update activities
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
        take: 3,
      });

      recentClients.forEach((client) => {
        // Creation activity
        activities.push({
          id: activityCounter++,
          type: ACTIVITY_TYPES.CLIENT_CREATED,
          description: `Client "${client.name}" created`,
          createdAt: client.createdAt,
          resourceId: client.id,
          metadata: {
            clientName: client.name,
            clientId: client.id,
            activity: `New OAuth2 client has been created.`,
            details: {
              isActive: client.isActive,
              isConfidential: client.isConfidential,
              description: client.description,
              createdAt: client.createdAt,
            },
          },
        });

        // Update activity (when creation and update dates differ)
        if (client.updatedAt.getTime() !== client.createdAt.getTime()) {
          activities.push({
            id: activityCounter++,
            type: ACTIVITY_TYPES.CLIENT_UPDATED,
            description: `Client "${client.name}" information updated`,
            createdAt: client.updatedAt,
            resourceId: client.id,
            metadata: {
              clientName: client.name,
              clientId: client.id,
              activity: `OAuth2 client information has been updated.`,
              details: {
                isActive: client.isActive,
                isConfidential: client.isConfidential,
                updatedAt: client.updatedAt,
              },
            },
          });
        }
      });

      // 3. Token creation/revocation activities
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
        take: 3,
      });

      recentTokens.forEach((token) => {
        // Token creation activity
        activities.push({
          id: activityCounter++,
          type: ACTIVITY_TYPES.TOKEN_CREATED,
          description: `Token issued for "${token.client?.name ?? 'Web application'}"`,
          createdAt: token.createdAt,
          resourceId: token.id,
          metadata: {
            clientName: token.client?.name,
            clientId: token.client?.id,
            activity: `New access token has been issued.`,
            details: {
              scopes: token.scopes,
              expiresAt: token.expiresAt,
              tokenId: token.id,
            },
          },
        });

        // Token revocation activity
        if (token.isRevoked) {
          activities.push({
            id: activityCounter++,
            type: ACTIVITY_TYPES.TOKEN_REVOKED,
            description: `Token revoked for "${token.client?.name ?? 'Web application'}"`,
            createdAt: token.revokedAt ?? new Date(),
            resourceId: token.id,
            metadata: {
              clientName: token.client?.name,
              clientId: token.client?.id,
              activity: `Access token has been revoked.`,
              reason:
                TOKEN_REVOCATION_REASON_DESCRIPTIONS[
                  TOKEN_REVOCATION_REASONS.USER_REVOKED_TOKENS
                ],
              details: {
                scopes: token.scopes,
                tokenId: token.id,
              },
            },
          });
        }
      });

      // Sort by time (newest first)
      activities.sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());

      // Return limited number
      return activities.slice(0, limit);
    } catch (error) {
      this.logger.error('Failed to get recent activities (legacy):', error);
      return [];
    }
  }

  async getConnectedApps(userId: number): Promise<ConnectedAppsResponseDto> {
    // Retrieve clients that issued tokens to the user
    const tokens = await this.tokenRepository.find({
      where: {
        user: { id: userId },
        isRevoked: false,
      },
      relations: ['user', 'client'],
      select: ['id', 'client', 'scopes', 'createdAt', 'expiresAt'],
      order: { createdAt: 'DESC' },
    });

    // Group latest token information by client
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
          scopes: token.scopes ?? [],
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
   * Invalidate user statistics cache (callable from outside)
   */
  async invalidateUserStatsCache(userId: number): Promise<void> {
    return this.cacheManagerService.invalidateUserStatsCache(userId);
  }

  /**
   * Invalidate user activities cache (callable from outside)
   */
  async invalidateUserActivitiesCache(userId: number): Promise<void> {
    return this.cacheManagerService.invalidateUserActivitiesCache(userId);
  }

  /**
   * Invalidate all user caches (for administrators)
   */
  async invalidateAllUserCaches(): Promise<void> {
    return this.cacheManagerService.invalidateAllUsersCache();
  }

  async revokeConnection(
    userId: number,
    clientId: number,
  ): Promise<RevokeConnectionResponseDto> {
    // Revoke all tokens for this user and client
    const tokens = await this.tokenRepository.find({
      where: {
        user: { id: userId },
        client: { id: clientId },
        isRevoked: false,
      },
      relations: ['user', 'client'],
    });

    const now = new Date();
    for (const token of tokens) {
      token.isRevoked = true;
      token.revokedAt = now;
      token.revokedReason = TOKEN_REVOCATION_REASONS.USER_REVOKED_CONNECTION;

      // Record token revoked event
      await this.statisticsRecordingService.recordTokenRevoked(
        userId,
        clientId,
        token.scopes ?? [],
        TOKEN_REVOCATION_REASONS.USER_REVOKED_CONNECTION,
        now,
      );
    }

    if (tokens.length > 0) {
      try {
        await this.tokenRepository.save(tokens);
      } catch (error) {
        this.logger.error(`Failed to save revoked tokens:`, error);
        throw error;
      }
    }

    // Invalidate related cache when revoking tokens
    for (const token of tokens) {
      if (token.accessToken) {
        await this.cacheManagerService.delCacheKey(
          CACHE_KEYS.oauth2.token(token.accessToken),
        );
      }
    }

    // Record audit log
    if (tokens.length > 0) {
      const client = tokens[0].client;
      try {
        await this.auditLogService.create({
          eventType: AuditEventType.TOKEN_REVOKED,
          severity: AuditSeverity.MEDIUM,
          description: `Tokens revoked due to connection revocation. Client: ${client?.name ?? 'Unknown'}`,
          userId,
          clientId,
          resourceId: clientId,
          resourceType: AUDIT_LOG_RESOURCE_TYPES.CLIENT_CONNECTION,
          metadata: {
            revokedTokensCount: tokens.length,
            clientName: client?.name,
            reason: TOKEN_REVOCATION_REASONS.USER_REVOKED_CONNECTION,
            tokenIds: tokens.map((t) => t.id),
          },
        });
      } catch (error) {
        this.logger.warn(
          'Failed to create audit log for connection revocation:',
          error,
        );
      }
    }

    return {
      success: true,
      revokedTokensCount: tokens.length,
      message: 'Connection successfully revoked.',
    };
  }

  /**
   * Retrieve token analysis metrics
   */
  async getTokenAnalytics(userId: number, days: number = 30) {
    return {
      usagePatterns: await this.tokenAnalyticsService.getTokenUsagePatterns(
        userId,
        days,
      ),
      clientPerformance:
        await this.tokenAnalyticsService.getClientPerformanceMetrics(userId),
      userActivity:
        await this.tokenAnalyticsService.getUserActivityMetrics(userId),
    };
  }

  /**
   * Retrieve security metrics
   */
  async getSecurityMetrics(userId: number, days: number = 30) {
    return {
      metrics: await this.securityMetricsService.getSecurityMetrics(
        userId,
        days,
      ),
      trends: await this.securityMetricsService.getSecurityTrends(userId, days),
    };
  }

  /**
   * Retrieve advanced statistics dashboard
   */
  async getAdvancedDashboardStats(userId: number, days: number = 30) {
    const cacheKey = CACHE_KEYS.dashboard.advancedStats(userId, days);

    try {
      // Check cache first
      const cached = await this.cacheManagerService.getCacheValue(cacheKey);
      if (cached) {
        return cached;
      }

      // Retrieve data in parallel
      const [tokenAnalytics, securityMetrics] = await Promise.all([
        this.getTokenAnalytics(userId, days),
        this.getSecurityMetrics(userId, days),
      ]);

      const result = {
        tokenAnalytics,
        securityMetrics,
        generatedAt: new Date(),
        period: `${days} days`,
      };

      // Save to cache (10 minutes)
      await this.cacheManagerService.setCacheValue(
        cacheKey,
        result,
        CACHE_CONFIG.TTL.DASHBOARD_ADVANCED_STATS,
      );

      return result;
    } catch (error) {
      this.logger.error('Error getting advanced dashboard stats:', error);
      throw error;
    }
  }
}
