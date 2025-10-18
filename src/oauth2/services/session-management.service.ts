import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as crypto from 'crypto';
import { User } from '../../auth/user.entity';
import { Client } from '../client.entity';
import { StructuredLogger } from '../../logging/structured-logger.service';

export interface SessionState {
  sessionId: string;
  userId: number;
  clientId: string;
  authenticatedAt: Date;
  lastActivity: Date;
  isActive: boolean;
  ipAddress?: string;
  userAgent?: string;
}

export interface SessionCheckResult {
  sessionState: 'changed' | 'unchanged' | 'error';
  sessionId?: string;
}

/**
 * OpenID Connect Session Management 1.0 Implementation
 */
@Injectable()
export class SessionManagementService {
  private readonly sessions = new Map<string, SessionState>();
  private readonly SESSION_TIMEOUT = 30 * 60 * 1000; // 30 minutes
  private readonly CHECK_SESSION_IFRAME_URL: string;

  constructor(
    private configService: ConfigService,
    private structuredLogger: StructuredLogger,
  ) {
    this.CHECK_SESSION_IFRAME_URL = `${this.configService.get('BASE_URL')}/connect/session/check`;

    // Session cleanup interval (every 5 minutes)
    setInterval(
      () => {
        this.cleanupExpiredSessions();
      },
      5 * 60 * 1000,
    );
  }

  /**
   * Create a new session
   */
  createSession(
    user: User,
    client: Client,
    ipAddress?: string,
    userAgent?: string,
  ): string {
    const sessionId = crypto.randomUUID();
    const now = new Date();

    const sessionState: SessionState = {
      sessionId,
      userId: user.id,
      clientId: client.clientId,
      authenticatedAt: now,
      lastActivity: now,
      isActive: true,
      ipAddress,
      userAgent,
    };

    this.sessions.set(sessionId, sessionState);

    this.structuredLogger.log(
      `Session created: ${sessionId}`,
      'SessionManagementService',
    );

    return sessionId;
  }

  /**
   * Check session status
   */
  checkSession(sessionId: string, clientId: string): SessionCheckResult {
    const session = this.sessions.get(sessionId);

    if (!session) {
      return { sessionState: 'error' };
    }

    if (!session.isActive || session.clientId !== clientId) {
      return { sessionState: 'error' };
    }

    // Check if session is expired
    const now = new Date();
    if (now.getTime() - session.lastActivity.getTime() > this.SESSION_TIMEOUT) {
      this.endSession(sessionId);
      return { sessionState: 'error' };
    }

    // Update last activity
    session.lastActivity = now;

    return {
      sessionState: 'unchanged',
      sessionId,
    };
  }

  /**
   * End session
   */
  endSession(sessionId: string): void {
    const session = this.sessions.get(sessionId);
    if (session) {
      session.isActive = false;
      this.sessions.delete(sessionId);

      this.structuredLogger.log(
        `Session ended: ${sessionId}`,
        'SessionManagementService',
      );
    }
  }

  /**
   * End all sessions for a user
   */
  endAllUserSessions(userId: number): void {
    for (const [sessionId, session] of this.sessions.entries()) {
      if (session.userId === userId) {
        this.endSession(sessionId);
      }
    }
  }

  /**
   * End all sessions for a client
   */
  endAllClientSessions(clientId: string): void {
    for (const [sessionId, session] of this.sessions.entries()) {
      if (session.clientId === clientId) {
        this.endSession(sessionId);
      }
    }
  }

  /**
   * Cleanup expired sessions
   */
  private cleanupExpiredSessions(): void {
    const now = new Date();
    const expiredSessions: string[] = [];

    for (const [sessionId, session] of this.sessions.entries()) {
      if (
        now.getTime() - session.lastActivity.getTime() >
        this.SESSION_TIMEOUT
      ) {
        expiredSessions.push(sessionId);
      }
    }

    for (const sessionId of expiredSessions) {
      this.endSession(sessionId);
    }

    if (expiredSessions.length > 0) {
      this.structuredLogger.log(
        `Expired sessions cleaned up: ${expiredSessions.length}`,
        'SessionManagementService',
      );
    }
  }

  /**
   * Create Session State (for OP iframe)
   */
  generateSessionState(
    clientId: string,
    sessionId: string,
    salt?: string,
  ): string {
    const actualSalt = salt || crypto.randomBytes(16).toString('hex');
    const hash = crypto
      .createHash('sha256')
      .update(clientId + ' ' + sessionId + ' ' + actualSalt)
      .digest('hex');

    return hash + '.' + actualSalt;
  }

  /**
   * Check Session iframe URL
   */
  getCheckSessionIframeUrl(): string {
    return this.CHECK_SESSION_IFRAME_URL;
  }

  /**
   * Get session statistics
   */
  getSessionStats(): {
    totalSessions: number;
    activeSessions: number;
    averageSessionDuration: number;
  } {
    const now = new Date();
    let totalDuration = 0;
    let activeSessions = 0;

    for (const session of this.sessions.values()) {
      if (session.isActive) {
        activeSessions++;
        totalDuration += now.getTime() - session.authenticatedAt.getTime();
      }
    }

    return {
      totalSessions: this.sessions.size,
      activeSessions,
      averageSessionDuration:
        activeSessions > 0 ? totalDuration / activeSessions : 0,
    };
  }

  /**
   * Get all active sessions for a user
   */
  getUserActiveSessions(userId: number): SessionState[] {
    const userSessions: SessionState[] = [];

    for (const session of this.sessions.values()) {
      if (session.userId === userId && session.isActive) {
        userSessions.push(session);
      }
    }

    return userSessions;
  }
}
