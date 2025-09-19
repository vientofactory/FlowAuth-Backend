import {
  Injectable,
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { SCOPES_KEY } from '../decorators/require-scopes.decorator';
import type { OAuth2AuthenticatedRequest } from '../../types/oauth2.types';

@Injectable()
export class OAuth2ScopeGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredScopes = this.reflector.getAllAndOverride<
      string[] | { type: 'any' | 'all'; scopes: string[] }
    >(SCOPES_KEY, [context.getHandler(), context.getClass()]);

    // 스코프 요구사항이 없으면 통과
    if (!requiredScopes) {
      return true;
    }

    const request = context
      .switchToHttp()
      .getRequest<OAuth2AuthenticatedRequest>();

    // OAuth2 인증이 되어있지 않으면 거부
    if (!request.user) {
      throw new UnauthorizedException('OAuth2 authentication required');
    }

    const userScopes = request.user.scopes || [];

    // 스코프 검증 로직
    const hasRequiredScopes = this.validateScopes(userScopes, requiredScopes);

    if (!hasRequiredScopes) {
      const scopesNeeded = Array.isArray(requiredScopes)
        ? requiredScopes
        : requiredScopes.scopes;
      throw new ForbiddenException(
        `Insufficient scope. Required: ${scopesNeeded.join(', ')}`,
      );
    }

    return true;
  }

  private validateScopes(
    userScopes: string[],
    requiredScopes: string[] | { type: 'any' | 'all'; scopes: string[] },
  ): boolean {
    // 단순 배열인 경우 (모든 스코프 필요)
    if (Array.isArray(requiredScopes)) {
      return requiredScopes.every((scope) => userScopes.includes(scope));
    }

    // 객체 형태인 경우
    const { type, scopes } = requiredScopes;

    if (type === 'any') {
      // 하나 이상의 스코프만 있으면 됨
      return scopes.some((scope) => userScopes.includes(scope));
    } else {
      // 모든 스코프가 필요함
      return scopes.every((scope) => userScopes.includes(scope));
    }
  }
}
