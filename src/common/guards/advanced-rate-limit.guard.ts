import {
  Injectable,
  CanActivate,
  ExecutionContext,
  HttpException,
  HttpStatus,
  Inject,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Request } from 'express';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import type { Cache } from 'cache-manager';

export interface RateLimitConfig {
  windowMs: number;
  maxRequests: number;
  keyGenerator?: (req: Request) => string;
  message?: string;
}

export const RATE_LIMIT_KEY = 'rate_limit';

export const RateLimit = (config: RateLimitConfig): MethodDecorator => {
  return (target: object, propertyKey?: string | symbol) => {
    Reflect.defineMetadata(
      RATE_LIMIT_KEY,
      config,
      target,
      propertyKey as string | symbol,
    );
  };
};

@Injectable()
export class AdvancedRateLimitGuard implements CanActivate {
  constructor(
    private reflector: Reflector,
    @Inject(CACHE_MANAGER) private cacheManager: Cache,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const config = this.reflector.getAllAndOverride<RateLimitConfig>(
      RATE_LIMIT_KEY,
      [context.getHandler(), context.getClass()],
    );

    if (!config) {
      return true;
    }

    const request = context.switchToHttp().getRequest<Request>();
    const key = this.generateKey(request, config.keyGenerator);

    const isAllowed = await this.checkRateLimit(key, config);

    if (!isAllowed) {
      throw new HttpException(
        {
          statusCode: HttpStatus.TOO_MANY_REQUESTS,
          message:
            config.message ?? 'Too many requests, please try again later',
          error: 'Too Many Requests',
        },
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }

    return true;
  }

  private generateKey(
    request: Request,
    keyGenerator?: (req: Request) => string,
  ): string {
    if (keyGenerator) {
      return keyGenerator(request);
    }

    const ip = this.getClientIP(request);
    const userAgent = request.headers['user-agent'] ?? 'unknown';
    const path = (request.route as { path?: string })?.path ?? request.path;

    return `rate_limit:${ip}:${this.hashString(userAgent)}:${path}`;
  }

  private getClientIP(request: Request): string {
    return (
      ((request.headers['cf-connecting-ip'] as string) ||
        (request.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ||
        (request.headers['x-real-ip'] as string) ||
        request.connection.remoteAddress) ??
      request.socket.remoteAddress ??
      'unknown'
    );
  }

  private hashString(str: string): string {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = (hash << 5) - hash + char;
      hash = hash & hash;
    }
    return hash.toString();
  }

  private async checkRateLimit(
    key: string,
    config: RateLimitConfig,
  ): Promise<boolean> {
    const now = Date.now();
    const windowStart = now - config.windowMs;

    const requests = (await this.cacheManager.get<number[]>(key)) ?? [];

    const validRequests = requests.filter(
      (timestamp) => timestamp > windowStart,
    );

    if (validRequests.length >= config.maxRequests) {
      return false;
    }

    validRequests.push(now);
    await this.cacheManager.set(key, validRequests, config.windowMs);

    return true;
  }
}
