import {
  Injectable,
  CanActivate,
  ExecutionContext,
  ForbiddenException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { PermissionUtils } from '../utils/permission.util';

export const PERMISSIONS_KEY = 'permissions';
// eslint-disable-next-line @typescript-eslint/no-unused-vars
export const REQUIRE_PERMISSIONS = (permissions: number[]) =>
  Reflector.createDecorator<number[]>({ key: PERMISSIONS_KEY });

interface RequestWithUser {
  user?: {
    permissions?: number;
  };
}

@Injectable()
export class PermissionsGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredPermissions = this.reflector.getAllAndOverride<number[]>(
      PERMISSIONS_KEY,
      [context.getHandler(), context.getClass()],
    );

    if (!requiredPermissions || requiredPermissions.length === 0) {
      return true; // 권한 요구사항이 없으면 통과
    }

    const request = context.switchToHttp().getRequest<RequestWithUser>();
    const user = request.user;

    if (!user || typeof user.permissions !== 'number') {
      throw new ForbiddenException('권한 정보가 없습니다.');
    }

    const hasPermission = PermissionUtils.hasAnyPermission(
      user.permissions,
      requiredPermissions,
    );

    if (!hasPermission) {
      throw new ForbiddenException('필요한 권한이 없습니다.');
    }

    return true;
  }
}
