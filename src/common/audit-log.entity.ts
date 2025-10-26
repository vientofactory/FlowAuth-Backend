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

export const RESOURCE_TYPES = {
  CLIENT: 'CLIENT',
  USER: 'USER',
  TOKEN: 'TOKEN',
  AUTHORIZATION_CODE: 'AUTHORIZATION_CODE',
  PERMISSION: 'PERMISSION',
  SYSTEM: 'SYSTEM',
} as const;

export type ResourceType = (typeof RESOURCE_TYPES)[keyof typeof RESOURCE_TYPES];

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

  static createClientCreatedEvent(
    userId: number,
    clientId: number,
    clientName: string,
    clientClientId: string,
    metadata: {
      redirectUris: number;
      grants: string[];
      scopes: string[];
      hasLogo?: boolean;
      hasTerms?: boolean;
      hasPolicy?: boolean;
    },
  ): Partial<AuditLog> {
    return {
      eventType: AuditEventType.CLIENT_CREATED,
      severity: AuditSeverity.MEDIUM,
      description: `OAuth2 클라이언트 "${clientName}"가 생성되었습니다.`,
      userId,
      clientId,
      resourceId: clientId,
      resourceType: RESOURCE_TYPES.CLIENT,
      metadata: {
        clientName,
        clientId: clientClientId,
        redirectUris: metadata.redirectUris,
        grants: metadata.grants.join(', '),
        scopes: metadata.scopes.join(', '),
        hasLogo: metadata.hasLogo ?? false,
        hasTerms: metadata.hasTerms ?? false,
        hasPolicy: metadata.hasPolicy ?? false,
      },
    };
  }

  static createClientUpdatedEvent(
    userId: number,
    clientId: number,
    clientName: string,
    clientClientId: string,
    action: string,
    metadata?: Record<string, unknown>,
  ): Partial<AuditLog> {
    return {
      eventType: AuditEventType.CLIENT_UPDATED,
      severity: AuditSeverity.HIGH,
      description: `OAuth2 클라이언트 "${clientName}"이(가) 업데이트되었습니다.`,
      userId,
      clientId,
      resourceId: clientId,
      resourceType: RESOURCE_TYPES.CLIENT,
      metadata: {
        clientName,
        clientId: clientClientId,
        action,
        ...metadata,
      },
    };
  }

  static createClientDeletedEvent(
    userId: number,
    clientId: number,
    clientName: string,
    clientClientId: string,
    deletedTokensCount: number,
    deletedAuthCodesCount: number,
    isAdminDeletion: boolean,
  ): Partial<AuditLog> {
    return {
      eventType: AuditEventType.CLIENT_DELETED,
      severity: AuditSeverity.HIGH,
      description: `OAuth2 클라이언트 "${clientName}"가 삭제되었습니다. ${deletedTokensCount}개의 토큰과 ${deletedAuthCodesCount}개의 인증 코드가 함께 삭제되었습니다.`,
      userId,
      clientId,
      resourceId: clientId,
      resourceType: RESOURCE_TYPES.CLIENT,
      metadata: {
        clientName,
        clientId: clientClientId,
        deletedTokensCount,
        deletedAuthCodesCount,
        isAdminDeletion,
      },
    };
  }

  static createTokenRevokedEvent(
    userId: number,
    clientId: number | undefined,
    tokenId: number,
    clientName: string | undefined,
    scopes: string[] | undefined,
    reason: string,
  ): Partial<AuditLog> {
    return {
      eventType: AuditEventType.TOKEN_REVOKED,
      severity: AuditSeverity.MEDIUM,
      description: `토큰이 취소되었습니다. 클라이언트: ${clientName ?? 'Unknown'}`,
      userId,
      clientId,
      resourceId: tokenId,
      resourceType: RESOURCE_TYPES.TOKEN,
      metadata: {
        tokenId,
        clientName,
        scopes,
        reason,
      },
    };
  }

  static createConnectionRevokedEvent(
    userId: number,
    clientId: number,
    clientName: string | undefined,
    revokedTokensCount: number,
    tokenIds: number[],
  ): Partial<AuditLog> {
    return {
      eventType: AuditEventType.TOKEN_REVOKED,
      severity: AuditSeverity.MEDIUM,
      description: `Tokens revoked due to connection revocation. Client: ${clientName ?? 'Unknown'}`,
      userId,
      clientId,
      resourceId: clientId,
      resourceType: RESOURCE_TYPES.CLIENT,
      metadata: {
        revokedTokensCount,
        clientName,
        reason: 'user_revoked_connection',
        tokenIds,
      },
    };
  }
}
