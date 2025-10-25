import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  ManyToOne,
  JoinColumn,
  CreateDateColumn,
  Index,
} from 'typeorm';
import { User } from '../auth/user.entity';
import { Client } from '../oauth2/client.entity';

export enum AuditEventType {
  // 인증 관련
  USER_LOGIN = 'user_login',
  USER_LOGOUT = 'user_logout',
  USER_LOGIN_FAILED = 'user_login_failed',
  USER_PASSWORD_CHANGE = 'user_password_change',

  // OAuth2 관련
  TOKEN_ISSUED = 'token_issued',
  TOKEN_REVOKED = 'token_revoked',
  TOKEN_EXPIRED = 'token_expired',
  TOKEN_REFRESHED = 'token_refreshed',
  TOKEN_USED = 'token_used',

  // 클라이언트 관련
  CLIENT_CREATED = 'client_created',
  CLIENT_UPDATED = 'client_updated',
  CLIENT_DELETED = 'client_deleted',

  // 권한 관련
  PERMISSION_GRANTED = 'permission_granted',
  PERMISSION_REVOKED = 'permission_revoked',

  // 보안 관련
  SUSPICIOUS_ACTIVITY = 'suspicious_activity',
  FAILED_AUTH_ATTEMPT = 'failed_auth_attempt',
  ACCOUNT_LOCKED = 'account_locked',

  // 시스템 관련
  SYSTEM_MAINTENANCE = 'system_maintenance',
  CONFIGURATION_CHANGE = 'configuration_change',
}

export enum AuditSeverity {
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  CRITICAL = 'critical',
}

@Entity()
@Index(['userId', 'createdAt'])
@Index(['clientId', 'createdAt'])
@Index(['eventType', 'createdAt'])
@Index(['severity', 'createdAt'])
@Index(['ipAddress'])
export class AuditLog {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({
    type: 'enum',
    enum: AuditEventType,
  })
  eventType: AuditEventType;

  @Column({
    type: 'enum',
    enum: AuditSeverity,
    default: AuditSeverity.LOW,
  })
  severity: AuditSeverity;

  @Column({ type: 'text' })
  description: string;

  @Column({ type: 'json', nullable: true })
  metadata?: Record<string, unknown>;

  @Column({ type: 'varchar', length: 45, nullable: true })
  ipAddress?: string;

  @Column({ type: 'varchar', length: 500, nullable: true })
  userAgent?: string;

  @Column({ type: 'varchar', length: 10, nullable: true })
  httpMethod?: string;

  @Column({ type: 'varchar', length: 500, nullable: true })
  endpoint?: string;

  @Column({ type: 'int', nullable: true })
  responseStatus?: number;

  @Column({ type: 'int', nullable: true })
  userId?: number;

  @ManyToOne(() => User, { nullable: true })
  @JoinColumn({ name: 'userId' })
  user?: User;

  @Column({ type: 'int', nullable: true })
  clientId?: number;

  @ManyToOne(() => Client, { nullable: true })
  @JoinColumn({ name: 'clientId' })
  client?: Client;

  @Column({ type: 'int', nullable: true })
  resourceId?: number;

  @Column({ type: 'varchar', length: 100, nullable: true })
  resourceType?: string;

  @CreateDateColumn()
  createdAt: Date;

  // 헬퍼 메서드들
  static createLoginEvent(
    userId: number,
    ipAddress?: string,
    userAgent?: string,
  ): Partial<AuditLog> {
    return {
      eventType: AuditEventType.USER_LOGIN,
      severity: AuditSeverity.LOW,
      description: '사용자가 로그인했습니다.',
      userId,
      ipAddress,
      userAgent,
      metadata: { action: 'login' },
    };
  }

  static createTokenIssuedEvent(
    userId: number,
    clientId: number,
    scopes: string[],
    ipAddress?: string,
  ): Partial<AuditLog> {
    return {
      eventType: AuditEventType.TOKEN_ISSUED,
      severity: AuditSeverity.LOW,
      description: `토큰이 발급되었습니다. 스코프: ${scopes.join(', ')}`,
      userId,
      clientId,
      ipAddress,
      metadata: { scopes, action: 'token_issued' },
    };
  }

  static createFailedAuthEvent(
    username: string,
    ipAddress?: string,
    reason?: string,
  ): Partial<AuditLog> {
    return {
      eventType: AuditEventType.FAILED_AUTH_ATTEMPT,
      severity: AuditSeverity.MEDIUM,
      description: `인증 실패: ${reason ?? '잘못된 자격 증명'}`,
      ipAddress,
      metadata: { username, reason, action: 'auth_failed' },
    };
  }

  static createSuspiciousActivityEvent(
    userId: number | null,
    activity: string,
    ipAddress?: string,
    severity: AuditSeverity = AuditSeverity.HIGH,
  ): Partial<AuditLog> {
    return {
      eventType: AuditEventType.SUSPICIOUS_ACTIVITY,
      severity,
      description: `의심스러운 활동 감지: ${activity}`,
      userId: userId ?? undefined,
      ipAddress,
      metadata: { activity, action: 'suspicious_activity' },
    };
  }
}
