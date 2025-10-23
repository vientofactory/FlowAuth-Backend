import {
  Injectable,
  ExecutionContext,
  UnauthorizedException,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { Observable } from 'rxjs';
import type { OAuth2JwtPayload } from '../../types/oauth2.types';

@Injectable()
export class OAuth2BearerGuard extends AuthGuard('oauth2') {
  canActivate(
    context: ExecutionContext,
  ): boolean | Promise<boolean> | Observable<boolean> {
    return super.canActivate(context);
  }

  handleRequest<TUser = OAuth2JwtPayload>(
    err: Error | null,
    user: OAuth2JwtPayload | null,
    info: unknown,
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    _context?: ExecutionContext,
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    _status?: number,
  ): TUser {
    try {
      // If there's a passport error, throw it
      if (err) {
        throw err;
      }

      // If no user is found, throw an unauthorized error
      if (!user) {
        let errorMessage = 'OAuth2 authentication required';

        if (info && typeof info === 'object' && info !== null) {
          const infoObj = info as Record<string, unknown>;

          if (infoObj.name === 'TokenExpiredError') {
            errorMessage =
              'OAuth2 token has expired. Please refresh your token.';
          } else if (infoObj.name === 'JsonWebTokenError') {
            errorMessage = 'Invalid OAuth2 token format.';
          } else if (typeof infoObj.message === 'string') {
            errorMessage = infoObj.message;
          }
        }

        throw new UnauthorizedException(errorMessage);
      }

      // Validate OAuth2 token structure
      if (!this.isValidOAuth2Payload(user)) {
        throw new UnauthorizedException('Invalid OAuth2 token');
      }

      return user as TUser;
    } catch (error: unknown) {
      if (error instanceof UnauthorizedException) {
        throw error;
      }

      throw new UnauthorizedException('Invalid OAuth2 token');
    }
  }

  private isValidOAuth2Payload(payload: unknown): payload is OAuth2JwtPayload {
    if (!payload || typeof payload !== 'object') {
      return false;
    }

    const p = payload as Record<string, unknown>;

    return (
      (typeof p.sub === 'string' || p.sub === null) &&
      (typeof p.client_id === 'string' || p.client_id === null) &&
      Array.isArray(p.scopes) &&
      typeof p.token_type === 'string' &&
      p.token_type === 'Bearer'
    );
  }
}
