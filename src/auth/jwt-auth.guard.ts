import {
  Injectable,
  ExecutionContext,
  UnauthorizedException,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { Observable } from 'rxjs';
import { User } from './user.entity';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
  canActivate(
    context: ExecutionContext,
  ): boolean | Promise<boolean> | Observable<boolean> {
    return super.canActivate(context);
  }

  handleRequest<TUser = User>(
    err: Error | null,
    user: User | null,
    info: unknown,
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    _context?: ExecutionContext,
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    _status?: number,
  ): TUser {
    console.log('[JwtAuthGuard] handleRequest called:', {
      hasError: !!err,
      hasUser: !!user,
      info: info,
    });

    try {
      // If there's a passport error, throw it
      if (err) {
        console.log('[JwtAuthGuard] Passport error:', err);
        throw err;
      }

      // If no user is found, throw an unauthorized error
      if (!user) {
        let errorMessage = 'Unauthorized';

        if (info && typeof info === 'object' && info !== null) {
          const infoObj = info as Record<string, unknown>;

          if (infoObj.name === 'TokenExpiredError') {
            errorMessage = 'Token has expired';
          } else if (infoObj.name === 'JsonWebTokenError') {
            errorMessage = 'Invalid token';
          } else if (typeof infoObj.message === 'string') {
            errorMessage = infoObj.message;
          }
        }

        console.log(
          '[JwtAuthGuard] No user found, throwing error:',
          errorMessage,
        );
        throw new UnauthorizedException(errorMessage);
      }

      console.log(
        '[JwtAuthGuard] Authentication successful for user:',
        user.id,
      );
      return user as TUser;
    } catch (error) {
      console.log('[JwtAuthGuard] Authentication failed:', error);
      if (error instanceof UnauthorizedException) {
        throw error;
      }

      throw new UnauthorizedException('Authentication failed');
    }
  }
}
