import {
  Injectable,
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  SetMetadata,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { PermissionUtils } from '../utils/permission.util';

export const PERMISSIONS_KEY = 'permissions';

// 간단한 권한 요구 데코레이터
export const RequirePermissions = (...permissions: number[]) =>
  SetMetadata(PERMISSIONS_KEY, permissions);

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

    if (!user || user.permissions === undefined || user.permissions === null) {
      throw new ForbiddenException('권한 정보가 없습니다.');
    }

    // permissions가 string인 경우 number로 변환
    const userPermissions =
      typeof user.permissions === 'string'
        ? parseInt(user.permissions, 10)
        : user.permissions;

    if (typeof userPermissions !== 'number' || isNaN(userPermissions)) {
      throw new ForbiddenException('권한 정보가 올바르지 않습니다.');
    }

    const hasPermission = PermissionUtils.hasAnyPermission(
      userPermissions,
      requiredPermissions,
    );

    if (!hasPermission) {
      throw new ForbiddenException('필요한 권한이 없습니다.');
    }

    return true;
  }
}
