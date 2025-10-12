import { Injectable, Inject, LoggerService } from '@nestjs/common';
import { WINSTON_MODULE_NEST_PROVIDER } from 'nest-winston';
import { Logger } from 'winston';

@Injectable()
export class StructuredLogger implements LoggerService {
  constructor(
    @Inject(WINSTON_MODULE_NEST_PROVIDER)
    private readonly logger: Logger,
  ) {}

  log(message: any, context?: string): void {
    this.logger.info(String(message), { context });
  }

  error(message: any, trace?: string, context?: string): void {
    this.logger.error(String(message), { context, trace });
  }

  warn(message: any, context?: string): void {
    this.logger.warn(String(message), { context });
  }

  debug(message: any, context?: string): void {
    this.logger.debug(String(message), { context });
  }

  verbose(message: any, context?: string): void {
    this.logger.verbose(String(message), { context });
  }

  // Structured logging methods
  logSecurityEvent(
    event: string,
    details: Record<string, any>,
    context?: string,
  ): void {
    this.logger.info('SECURITY_EVENT', {
      event,
      ...details,
      context,
      timestamp: new Date().toISOString(),
    });
  }

  logAuthAttempt(
    success: boolean,
    userId?: string,
    ip?: string,
    context?: string,
  ): void {
    this.logger.info('AUTH_ATTEMPT', {
      success,
      userId,
      ip,
      context,
      timestamp: new Date().toISOString(),
    });
  }

  logApiRequest(
    method: string,
    url: string,
    statusCode: number,
    duration: number,
    userId?: string,
    ip?: string,
  ): void {
    this.logger.info('API_REQUEST', {
      method,
      url,
      statusCode,
      duration,
      userId,
      ip,
      timestamp: new Date().toISOString(),
    });
  }

  logError(
    error: Error,
    context?: string,
    additionalData?: Record<string, any>,
  ): void {
    this.logger.error('APPLICATION_ERROR', {
      message: error.message,
      stack: error.stack,
      name: error.name,
      context,
      ...additionalData,
      timestamp: new Date().toISOString(),
    });
  }

  logRateLimitExceeded(
    identifier: string,
    limit: number,
    windowMs: number,
  ): void {
    this.logger.warn('RATE_LIMIT_EXCEEDED', {
      identifier,
      limit,
      windowMs,
      timestamp: new Date().toISOString(),
    });
  }

  logSecurity(
    event: string,
    details: Record<string, any>,
    context?: string,
  ): void {
    this.logger.warn('SECURITY_ALERT', {
      event,
      severity: 'HIGH',
      ...details,
      context,
      timestamp: new Date().toISOString(),
    });
  }

  logTokenRotation(
    tokenFamily: string,
    generation: number,
    clientId: string,
    userId?: string,
  ): void {
    this.logger.info('TOKEN_ROTATION', {
      tokenFamily,
      generation,
      clientId,
      userId,
      timestamp: new Date().toISOString(),
    });
  }
}
