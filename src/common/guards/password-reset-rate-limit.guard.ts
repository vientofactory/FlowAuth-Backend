import {
  Injectable,
  CanActivate,
  ExecutionContext,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import { Request } from 'express';
import { CacheManagerService } from '../../cache/cache-manager.service';
import { RATE_LIMIT_CONFIGS } from '../../constants/security.constants';
import { createHash } from 'crypto';

@Injectable()
export class PasswordResetRateLimitGuard implements CanActivate {
  constructor(private cacheManagerService: CacheManagerService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<Request>();

    // IP 기반 레이트리밋 체크
    const ipKey = this.generateIpKey(request);
    const ipAllowed = await this.checkRateLimit(
      ipKey,
      RATE_LIMIT_CONFIGS.AUTH_PASSWORD_RESET,
    );

    if (!ipAllowed) {
      throw new HttpException(
        {
          statusCode: HttpStatus.TOO_MANY_REQUESTS,
          message: RATE_LIMIT_CONFIGS.AUTH_PASSWORD_RESET.message,
          error: 'Too Many Requests',
          type: 'IP_RATE_LIMIT',
        },
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }

    // 이메일 기반 레이트리밋 체크
    const emailKey = this.generateEmailKey(request);
    const emailAllowed = await this.checkRateLimit(
      emailKey,
      RATE_LIMIT_CONFIGS.AUTH_PASSWORD_RESET_EMAIL,
    );

    if (!emailAllowed) {
      throw new HttpException(
        {
          statusCode: HttpStatus.TOO_MANY_REQUESTS,
          message: RATE_LIMIT_CONFIGS.AUTH_PASSWORD_RESET_EMAIL.message,
          error: 'Too Many Requests',
          type: 'EMAIL_RATE_LIMIT',
        },
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }

    return true;
  }

  private generateIpKey(request: Request): string {
    const ip = this.getClientIP(request);
    return `rate_limit:ip:${ip}:${request.path || 'unknown'}`;
  }

  private generateEmailKey(request: Request): string {
    let email = 'unknown';
    try {
      const body = request.body as { email?: string };
      email = body?.email ?? 'unknown';
    } catch {
      email = 'unknown';
    }
    const emailHash = createHash('md5')
      .update(email.toLowerCase())
      .digest('hex')
      .substring(0, 12);
    return `rate_limit:email:${emailHash}:${request.path || 'unknown'}`;
  }

  private getClientIP(request: Request): string {
    return (
      ((request.headers['cf-connecting-ip'] as string) ||
        (request.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ||
        (request.headers['x-real-ip'] as string) ||
        request.connection?.remoteAddress) ??
      request.socket?.remoteAddress ??
      'unknown'
    );
  }

  private async checkRateLimit(
    key: string,
    config: { windowMs: number; maxRequests: number },
  ): Promise<boolean> {
    const now = Date.now();
    const windowStart = now - config.windowMs;

    const requests =
      (await this.cacheManagerService.getCacheValue<number[]>(key)) ?? [];

    const validRequests = requests.filter(
      (timestamp) => timestamp > windowStart,
    );

    if (validRequests.length >= config.maxRequests) {
      return false;
    }

    validRequests.push(now);
    await this.cacheManagerService.setCacheValue(
      key,
      validRequests,
      Math.ceil(config.windowMs / 1000), // TTL in seconds
    );

    return true;
  }
}
