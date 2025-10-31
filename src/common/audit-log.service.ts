import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, LessThan, MoreThan } from 'typeorm';
import { AuditLog, AuditEventType, AuditSeverity } from './audit-log.entity';
import { CACHE_KEYS } from '../constants/cache.constants';
import { CacheManagerService } from '../cache/cache-manager.service';

@Injectable()
export class AuditLogService {
  private readonly logger = new Logger(AuditLogService.name);

  constructor(
    @InjectRepository(AuditLog)
    private auditLogRepository: Repository<AuditLog>,
    private cacheManagerService: CacheManagerService,
  ) {}

  /**
   * 감사 로그 생성
   */
  async create(auditLogData: Partial<AuditLog>): Promise<AuditLog> {
    try {
      const auditLog = this.auditLogRepository.create(auditLogData);
      const savedAuditLog = await this.auditLogRepository.save(auditLog);

      // 감사 로그 기록 시 관련 캐시 무효화 (사용자 활동 캐시)
      if (savedAuditLog.userId) {
        try {
          const commonLimits = [10, 20, 50];
          for (const limit of commonLimits) {
            const cacheKey = CACHE_KEYS.dashboard.activities(
              savedAuditLog.userId,
              limit,
            );
            await this.cacheManagerService.delCacheKey(cacheKey);
          }
        } catch (cacheError) {
          // 캐시 무효화 실패는 로그만 기록하고 감사 로그 생성은 계속 진행
          this.logger.warn(
            'Failed to invalidate activity cache after audit log creation:',
            cacheError,
          );
        }
      }

      return savedAuditLog;
    } catch (error) {
      this.logger.error('Failed to create audit log:', error);
      throw error;
    }
  }

  /**
   * 사용자별 감사 로그 조회
   */
  async getUserAuditLogs(
    userId: number,
    options: {
      limit?: number;
      offset?: number;
      eventTypes?: AuditEventType[];
      severity?: AuditSeverity[];
      startDate?: Date;
      endDate?: Date;
    } = {},
  ): Promise<[AuditLog[], number]> {
    const {
      limit = 50,
      offset = 0,
      eventTypes,
      severity,
      startDate,
      endDate,
    } = options;

    const queryBuilder = this.auditLogRepository
      .createQueryBuilder('audit')
      .leftJoinAndSelect('audit.user', 'user')
      .leftJoinAndSelect('audit.client', 'client')
      .where('audit.userId = :userId', { userId })
      .orderBy('audit.createdAt', 'DESC')
      .limit(limit)
      .offset(offset);

    if (eventTypes && eventTypes.length > 0) {
      queryBuilder.andWhere('audit.eventType IN (:...eventTypes)', {
        eventTypes,
      });
    }

    if (severity && severity.length > 0) {
      queryBuilder.andWhere('audit.severity IN (:...severity)', {
        severity,
      });
    }

    if (startDate && endDate) {
      queryBuilder.andWhere('audit.createdAt BETWEEN :startDate AND :endDate', {
        startDate,
        endDate,
      });
    } else if (startDate) {
      queryBuilder.andWhere('audit.createdAt >= :startDate', { startDate });
    } else if (endDate) {
      queryBuilder.andWhere('audit.createdAt <= :endDate', { endDate });
    }

    return await queryBuilder.getManyAndCount();
  }

  /**
   * 사용자별 실패한 인증 시도 조회 (metadata.username으로 필터링)
   */
  async getFailedAuthAttemptsByEmail(
    email: string,
    options: {
      limit?: number;
      offset?: number;
      startDate?: Date;
      endDate?: Date;
    } = {},
  ): Promise<[AuditLog[], number]> {
    const { limit = 50, offset = 0, startDate, endDate } = options;

    const queryBuilder = this.auditLogRepository
      .createQueryBuilder('audit')
      .leftJoinAndSelect('audit.user', 'user')
      .leftJoinAndSelect('audit.client', 'client')
      .where('audit.eventType = :eventType', {
        eventType: AuditEventType.FAILED_AUTH_ATTEMPT,
      })
      .andWhere("JSON_EXTRACT(audit.metadata, '$.username') = :email", {
        email,
      })
      .orderBy('audit.createdAt', 'DESC')
      .limit(limit)
      .offset(offset);

    if (startDate && endDate) {
      queryBuilder.andWhere('audit.createdAt BETWEEN :startDate AND :endDate', {
        startDate,
        endDate,
      });
    } else if (startDate) {
      queryBuilder.andWhere('audit.createdAt >= :startDate', { startDate });
    } else if (endDate) {
      queryBuilder.andWhere('audit.createdAt <= :endDate', { endDate });
    }

    return await queryBuilder.getManyAndCount();
  }

  /**
   * 보안 이벤트 조회 (높은 심각도 이벤트)
   */
  async getSecurityEvents(
    options: {
      limit?: number;
      offset?: number;
      startDate?: Date;
      endDate?: Date;
      includeUserId?: boolean;
    } = {},
  ): Promise<[AuditLog[], number]> {
    const {
      limit = 100,
      offset = 0,
      startDate,
      endDate,
      includeUserId,
    } = options;

    const queryBuilder = this.auditLogRepository
      .createQueryBuilder('audit')
      .leftJoinAndSelect('audit.user', 'user')
      .leftJoinAndSelect('audit.client', 'client')
      .where('audit.severity IN (:...severities)', {
        severities: [AuditSeverity.HIGH, AuditSeverity.CRITICAL],
      })
      .orWhere('audit.eventType IN (:...eventTypes)', {
        eventTypes: [
          AuditEventType.FAILED_AUTH_ATTEMPT,
          AuditEventType.SUSPICIOUS_ACTIVITY,
          AuditEventType.TOKEN_REVOKED,
        ],
      })
      .orderBy('audit.createdAt', 'DESC')
      .limit(limit)
      .offset(offset);

    if (startDate && endDate) {
      queryBuilder.andWhere('audit.createdAt BETWEEN :startDate AND :endDate', {
        startDate,
        endDate,
      });
    }

    if (includeUserId) {
      queryBuilder.andWhere('audit.userId IS NOT NULL');
    }

    return await queryBuilder.getManyAndCount();
  }

  /**
   * 통계용 감사 로그 집계
   */
  async getAuditStats(
    userId: number,
    days: number = 30,
  ): Promise<{
    totalEvents: number;
    eventsByType: Record<AuditEventType, number>;
    eventsBySeverity: Record<AuditSeverity, number>;
    recentFailedAttempts: number;
    suspiciousActivities: number;
  }> {
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - days);

    const [logs] = await this.auditLogRepository.findAndCount({
      where: {
        userId,
        createdAt: MoreThan(startDate),
      },
    });

    const eventsByType = logs.reduce(
      (acc, log) => {
        acc[log.eventType] = (acc[log.eventType] || 0) + 1;
        return acc;
      },
      {} as Record<AuditEventType, number>,
    );

    const eventsBySeverity = logs.reduce(
      (acc, log) => {
        acc[log.severity] = (acc[log.severity] || 0) + 1;
        return acc;
      },
      {} as Record<AuditSeverity, number>,
    );

    const recentFailedAttempts = logs.filter(
      (log) => log.eventType === AuditEventType.FAILED_AUTH_ATTEMPT,
    ).length;

    const suspiciousActivities = logs.filter(
      (log) => log.eventType === AuditEventType.SUSPICIOUS_ACTIVITY,
    ).length;

    return {
      totalEvents: logs.length,
      eventsByType,
      eventsBySeverity,
      recentFailedAttempts,
      suspiciousActivities,
    };
  }

  /**
   * 오래된 감사 로그 정리 (30일 이상 된 로그 삭제)
   */
  async cleanupOldLogs(daysToKeep: number = 30): Promise<number> {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - daysToKeep);

    const result = await this.auditLogRepository.delete({
      createdAt: LessThan(cutoffDate),
    });

    return result.affected ?? 0;
  }

  /**
   * IP 주소별 활동 분석
   */
  async getActivityByIpAddress(
    userId: number,
    days: number = 30,
  ): Promise<Array<{ ipAddress: string; count: number; lastActivity: Date }>> {
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - days);

    const result = await this.auditLogRepository
      .createQueryBuilder('audit')
      .select('audit.ipAddress', 'ipAddress')
      .addSelect('COUNT(*)', 'count')
      .addSelect('MAX(audit.createdAt)', 'lastActivity')
      .where('audit.userId = :userId', { userId })
      .andWhere('audit.ipAddress IS NOT NULL')
      .andWhere('audit.createdAt >= :startDate', { startDate })
      .groupBy('audit.ipAddress')
      .orderBy('count', 'DESC')
      .limit(10)
      .getRawMany();

    return result.map(
      (row: { ipAddress: string; count: string; lastActivity: string }) => ({
        ipAddress: row.ipAddress,
        count: parseInt(row.count, 10),
        lastActivity: new Date(row.lastActivity),
      }),
    );
  }
}
