import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, MoreThan, Between } from 'typeorm';
import {
  AuditLog,
  AuditEventType,
  AuditSeverity,
} from '../common/audit-log.entity';
import { User } from '../auth/user.entity';
import { Client } from '../oauth2/client.entity';
import { Token } from '../oauth2/token.entity';

export interface SecurityAlert {
  id: number;
  type:
    | 'suspicious_activity'
    | 'failed_login'
    | 'unusual_pattern'
    | 'security_breach';
  severity: AuditSeverity;
  description: string;
  userId?: number;
  clientId?: number;
  timestamp: Date;
  metadata: Record<string, unknown>;
}

export interface SecurityMetrics {
  totalAlerts: number;
  criticalAlerts: number;
  highSeverityAlerts: number;
  mediumSeverityAlerts: number;
  lowSeverityAlerts: number;
  alertsByType: Record<string, number>;
  recentAlerts: SecurityAlert[];
  topRiskyUsers: RiskyUser[];
  topRiskyClients: RiskyClient[];
  securityScore: number; // 0-100, higher is better
  threatLevel: 'low' | 'medium' | 'high' | 'critical';
}

export interface RiskyUser {
  userId: number;
  username: string;
  riskScore: number;
  failedAttempts: number;
  suspiciousActivities: number;
  lastActivity: Date;
}

export interface RiskyClient {
  clientId: number;
  clientName: string;
  riskScore: number;
  revokedTokens: number;
  suspiciousRequests: number;
  lastActivity: Date;
}

export interface SecurityTrend {
  date: string;
  alerts: number;
  failedLogins: number;
  suspiciousActivities: number;
  blockedRequests: number;
}

@Injectable()
export class SecurityMetricsService {
  private readonly logger = new Logger(SecurityMetricsService.name);

  constructor(
    @InjectRepository(AuditLog)
    private auditLogRepository: Repository<AuditLog>,
    @InjectRepository(User)
    private userRepository: Repository<User>,
    @InjectRepository(Client)
    private clientRepository: Repository<Client>,
    @InjectRepository(Token)
    private tokenRepository: Repository<Token>,
  ) {}

  /**
   * 보안 메트릭스 계산
   */
  async getSecurityMetrics(
    userId: number,
    days: number = 30,
  ): Promise<SecurityMetrics> {
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - days);

    try {
      // 보안 관련 감사 로그 조회
      const securityLogs = await this.auditLogRepository.find({
        where: [
          {
            userId,
            eventType: AuditEventType.FAILED_AUTH_ATTEMPT,
            createdAt: MoreThan(startDate),
          },
          {
            userId,
            eventType: AuditEventType.SUSPICIOUS_ACTIVITY,
            createdAt: MoreThan(startDate),
          },
          {
            userId,
            eventType: AuditEventType.ACCOUNT_LOCKED,
            createdAt: MoreThan(startDate),
          },
        ],
        order: { createdAt: 'DESC' },
      });

      // 심각도별 알림 수 계산
      const alertsBySeverity = {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
      };

      const alertsByTypeMap = new Map<string, number>();

      securityLogs.forEach((log) => {
        alertsBySeverity[log.severity] =
          (alertsBySeverity[log.severity] || 0) + 1;

        const typeKey = this.mapEventTypeToAlertType(log.eventType);
        alertsByTypeMap.set(typeKey, (alertsByTypeMap.get(typeKey) ?? 0) + 1);
      });

      const alertsByType = Object.fromEntries(alertsByTypeMap);

      // 최근 알림 (최대 10개)
      const recentAlerts: SecurityAlert[] = securityLogs
        .slice(0, 10)
        .map((log) => ({
          id: log.id,
          type: this.mapEventTypeToAlertType(log.eventType),
          severity: log.severity,
          description: this.generateAlertDescription(log),
          userId: log.userId,
          clientId: log.clientId,
          timestamp: log.createdAt,
          metadata: log.metadata ?? {},
        }));

      // 위험 사용자 분석
      const topRiskyUsers = await this.getTopRiskyUsers(userId, startDate);

      // 위험 클라이언트 분석
      const topRiskyClients = await this.getTopRiskyClients(userId, startDate);

      // 보안 점수 계산 (0-100, 높을수록 좋음)
      const securityScore = this.calculateSecurityScore(
        securityLogs.length,
        alertsBySeverity,
        topRiskyUsers.length,
        days,
      );

      // 위협 수준 결정
      const threatLevel = this.determineThreatLevel(securityScore);

      return {
        totalAlerts: securityLogs.length,
        criticalAlerts: alertsBySeverity.critical,
        highSeverityAlerts: alertsBySeverity.high,
        mediumSeverityAlerts: alertsBySeverity.medium,
        lowSeverityAlerts: alertsBySeverity.low,
        alertsByType,
        recentAlerts,
        topRiskyUsers,
        topRiskyClients,
        securityScore,
        threatLevel,
      };
    } catch (error) {
      this.logger.error('Error getting security metrics:', error);
      throw error;
    }
  }

  /**
   * 보안 트렌드 분석
   */
  async getSecurityTrends(
    userId: number,
    days: number = 30,
  ): Promise<SecurityTrend[]> {
    const trends: SecurityTrend[] = [];
    const now = new Date();

    try {
      for (let i = days - 1; i >= 0; i--) {
        const date = new Date(now);
        date.setDate(date.getDate() - i);
        const nextDate = new Date(date);
        nextDate.setDate(nextDate.getDate() + 1);

        const dayLogs = await this.auditLogRepository.find({
          where: [
            {
              userId,
              eventType: AuditEventType.FAILED_AUTH_ATTEMPT,
              createdAt: Between(date, nextDate),
            },
            {
              userId,
              eventType: AuditEventType.SUSPICIOUS_ACTIVITY,
              createdAt: Between(date, nextDate),
            },
          ],
        });

        const failedLogins = dayLogs.filter(
          (log) => log.eventType === AuditEventType.FAILED_AUTH_ATTEMPT,
        ).length;

        const suspiciousActivities = dayLogs.filter(
          (log) => log.eventType === AuditEventType.SUSPICIOUS_ACTIVITY,
        ).length;

        trends.push({
          date: date.toISOString().split('T')[0],
          alerts: dayLogs.length,
          failedLogins,
          suspiciousActivities,
          blockedRequests: 0, // TODO: 차단된 요청 수 계산 로직 추가
        });
      }

      return trends;
    } catch (error) {
      this.logger.error('Error getting security trends:', error);
      return [];
    }
  }

  /**
   * 실시간 보안 알림 생성
   */
  async generateSecurityAlert(
    eventType: AuditEventType,
    severity: AuditSeverity,
    userId?: number,
    clientId?: number,
    metadata?: Record<string, unknown>,
  ): Promise<SecurityAlert> {
    try {
      const alert: SecurityAlert = {
        id: Date.now(), // 임시 ID, 실제로는 DB에서 생성
        type: this.mapEventTypeToAlertType(eventType),
        severity,
        description: this.generateAlertDescription({
          eventType,
          severity,
          metadata,
        }),
        userId,
        clientId,
        timestamp: new Date(),
        metadata: metadata ?? {},
      };

      // 실제로는 DB에 저장
      await this.auditLogRepository.save({
        eventType,
        severity,
        userId,
        clientId,
        metadata,
        ipAddress: (metadata as { ipAddress?: string })?.ipAddress,
        userAgent: (metadata as { userAgent?: string })?.userAgent,
      });

      return alert;
    } catch (error) {
      this.logger.error('Error generating security alert:', error);
      throw error;
    }
  }

  /**
   * 위험 사용자 분석
   */
  private async getTopRiskyUsers(
    ownerId: number,
    startDate: Date,
  ): Promise<RiskyUser[]> {
    try {
      // 모든 사용자 조회 (ownerId는 보안 메트릭스 조회 권한 확인용으로만 사용)
      const users = await this.userRepository.find({
        select: ['id', 'username', 'lastLoginAt'],
      });

      const riskyUsers: RiskyUser[] = [];

      for (const user of users) {
        const failedAttempts = await this.auditLogRepository.count({
          where: {
            userId: user.id,
            eventType: AuditEventType.FAILED_AUTH_ATTEMPT,
            createdAt: MoreThan(startDate),
          },
        });

        const suspiciousActivities = await this.auditLogRepository.count({
          where: {
            userId: user.id,
            eventType: AuditEventType.SUSPICIOUS_ACTIVITY,
            createdAt: MoreThan(startDate),
          },
        });

        if (failedAttempts > 0 || suspiciousActivities > 0) {
          const riskScore = Math.min(
            (failedAttempts * 10 + suspiciousActivities * 20) / 10,
            100,
          );

          riskyUsers.push({
            userId: user.id,
            username: user.username,
            riskScore: Math.round(riskScore),
            failedAttempts,
            suspiciousActivities,
            lastActivity: user.lastLoginAt ?? new Date(),
          });
        }
      }

      return riskyUsers.sort((a, b) => b.riskScore - a.riskScore).slice(0, 10);
    } catch (error) {
      this.logger.error('Error getting top risky users:', error);
      return [];
    }
  }

  /**
   * 위험 클라이언트 분석
   */
  private async getTopRiskyClients(
    ownerId: number,
    startDate: Date,
  ): Promise<RiskyClient[]> {
    try {
      const clients = await this.clientRepository.find({
        where: { userId: ownerId },
        select: ['id', 'name'],
      });

      const riskyClients: RiskyClient[] = [];

      for (const client of clients) {
        const revokedTokens = await this.tokenRepository.count({
          where: {
            client: { id: client.id },
            isRevoked: true,
            createdAt: MoreThan(startDate),
          },
        });

        const suspiciousRequests = await this.auditLogRepository.count({
          where: {
            clientId: client.id,
            eventType: AuditEventType.SUSPICIOUS_ACTIVITY,
            createdAt: MoreThan(startDate),
          },
        });

        if (revokedTokens > 0 || suspiciousRequests > 0) {
          const riskScore = Math.min(
            (revokedTokens * 15 + suspiciousRequests * 25) / 10,
            100,
          );

          // 마지막 활동 조회
          const lastToken = await this.tokenRepository.findOne({
            where: { client: { id: client.id } },
            order: { createdAt: 'DESC' },
            select: ['createdAt'],
          });

          riskyClients.push({
            clientId: client.id,
            clientName: client.name,
            riskScore: Math.round(riskScore),
            revokedTokens,
            suspiciousRequests,
            lastActivity: lastToken?.createdAt ?? new Date(),
          });
        }
      }

      return riskyClients
        .sort((a, b) => b.riskScore - a.riskScore)
        .slice(0, 10);
    } catch (error) {
      this.logger.error('Error getting top risky clients:', error);
      return [];
    }
  }

  /**
   * 보안 점수 계산
   */
  private calculateSecurityScore(
    totalAlerts: number,
    alertsBySeverity: Record<string, number>,
    riskyUsersCount: number,
    days: number,
  ): number {
    // 기본 점수 100에서 감점
    let score = 100;

    // 알림 수에 따른 감점 (일일 평균 기준)
    const avgAlertsPerDay = totalAlerts / days;
    score -= Math.min(avgAlertsPerDay * 5, 30);

    // 심각도별 감점
    score -= alertsBySeverity.critical * 10;
    score -= alertsBySeverity.high * 5;
    score -= alertsBySeverity.medium * 2;
    score -= alertsBySeverity.low * 1;

    // 위험 사용자 수에 따른 감점
    score -= riskyUsersCount * 3;

    return Math.max(0, Math.round(score));
  }

  /**
   * 위협 수준 결정
   */
  private determineThreatLevel(
    score: number,
  ): 'low' | 'medium' | 'high' | 'critical' {
    if (score >= 80) return 'low';
    if (score >= 60) return 'medium';
    if (score >= 40) return 'high';
    return 'critical';
  }

  /**
   * 이벤트 타입을 알림 타입으로 매핑
   */
  private mapEventTypeToAlertType(
    eventType: AuditEventType,
  ): SecurityAlert['type'] {
    switch (eventType) {
      case AuditEventType.FAILED_AUTH_ATTEMPT:
        return 'failed_login';
      case AuditEventType.SUSPICIOUS_ACTIVITY:
        return 'suspicious_activity';
      case AuditEventType.ACCOUNT_LOCKED:
        return 'security_breach';
      default:
        return 'unusual_pattern';
    }
  }

  /**
   * 알림 설명 생성
   */
  private generateAlertDescription(log: Partial<AuditLog>): string {
    switch (log.eventType) {
      case AuditEventType.FAILED_AUTH_ATTEMPT:
        return '실패한 인증 시도가 감지되었습니다.';
      case AuditEventType.SUSPICIOUS_ACTIVITY:
        return '의심스러운 활동이 감지되었습니다.';
      case AuditEventType.ACCOUNT_LOCKED:
        return '계정이 잠금 처리되었습니다.';
      default:
        return '비정상적인 패턴이 감지되었습니다.';
    }
  }
}
