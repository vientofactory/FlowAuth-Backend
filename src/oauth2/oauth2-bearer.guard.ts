import {
  Injectable,
  CanActivate,
  ExecutionContext,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import type { Request } from 'express';
import type { OAuth2JwtPayload } from '../types/oauth2.types';

interface AuthenticatedRequest extends Request {
  user: OAuth2JwtPayload;
}

@Injectable()
export class OAuth2BearerGuard implements CanActivate {
  constructor(
    private jwtService: JwtService,
    private configService: ConfigService,
  ) {}

  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest<AuthenticatedRequest>();
    const authHeader = request.headers.authorization;

    if (!authHeader?.startsWith('Bearer ')) {
      throw new UnauthorizedException('Bearer token required');
    }

    const token = authHeader.substring(7);

    try {
      // OAuth2 토큰 검증
      const payload: unknown = this.jwtService.verify(token, {
        secret: this.configService.get<string>('JWT_SECRET'),
      });

      // OAuth2 토큰 구조 검증
      if (!this.isValidOAuth2Payload(payload)) {
        throw new UnauthorizedException('Invalid OAuth2 token structure');
      }

      // Add user payload to request
      request.user = payload;
      return true;
    } catch (error) {
      if (error instanceof UnauthorizedException) {
        throw error;
      }
      throw new UnauthorizedException('Invalid token');
    }
  }

  private isValidOAuth2Payload(payload: unknown): payload is OAuth2JwtPayload {
    if (!payload || typeof payload !== 'object') {
      return false;
    }

    const p = payload as Record<string, unknown>;

    return (
      typeof p.client_id === 'string' &&
      Array.isArray(p.scopes) &&
      p.scopes.every((scope: unknown) => typeof scope === 'string') &&
      p.token_type === 'Bearer' &&
      (p.sub === null || typeof p.sub === 'number')
    );
  }
}
