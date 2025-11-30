import {
  Injectable,
  ExecutionContext,
  UnauthorizedException,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { Observable } from 'rxjs';
import type { User } from '../user.entity';
import { USER_TYPES } from '@flowauth/shared';

@Injectable()
export class LoginTokenGuard extends AuthGuard('jwt') {
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
    try {
      // If there's a passport error, throw it
      if (err) {
        throw err;
      }

      // If no user is found, throw an unauthorized error
      if (!user) {
        let errorMessage = 'Authentication required';

        if (info && typeof info === 'object' && info !== null) {
          const infoObj = info as Record<string, unknown>;

          if (infoObj.name === 'TokenExpiredError') {
            errorMessage = 'Login token has expired. Please log in again.';
          } else if (infoObj.name === 'JsonWebTokenError') {
            errorMessage = 'Invalid login token format.';
          } else if (typeof infoObj.message === 'string') {
            errorMessage = infoObj.message;
          }
        }

        throw new UnauthorizedException(errorMessage);
      }

      // Validate user object
      if (!this.isValidUser(user)) {
        throw new UnauthorizedException('Invalid user');
      }

      return user as TUser;
    } catch (error: unknown) {
      if (error instanceof UnauthorizedException) {
        throw error;
      }

      throw new UnauthorizedException('Invalid login token');
    }
  }

  // Type guard for user object
  private isValidUser(user: any): user is User {
    if (!user || typeof user !== 'object') {
      return false;
    }

    const u = user as Record<string, any>;

    return (
      typeof u.id === 'number' &&
      typeof u.username === 'string' &&
      typeof u.permissions === 'number' &&
      typeof u.email === 'string' &&
      typeof u.firstName === 'string' &&
      typeof u.lastName === 'string' &&
      typeof u.userType === 'string' &&
      (Object.values(USER_TYPES) as string[]).includes(u.userType)
    );
  }
}
