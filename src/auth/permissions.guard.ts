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

// 간단한 권한 요구 데코레이터 (기본: 하나라도 있으면 통과)
export const RequirePermissions = (...permissions: number[]) =>
  SetMetadata(PERMISSIONS_KEY, { permissions, requireAll: false });

// 모든 권한이 필요할 때 사용하는 데코레이터
export const RequireAllPermissions = (...permissions: number[]) =>
  SetMetadata(PERMISSIONS_KEY, { permissions, requireAll: true });

// 하나라도 권한이 있으면 통과하는 데코레이터 (명시적)
export const RequireAnyPermissions = (...permissions: number[]) =>
  SetMetadata(PERMISSIONS_KEY, { permissions, requireAll: false });

interface RequestWithUser {
  user?: {
    permissions?: number;
  };
}

@Injectable()
export class PermissionsGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const permissionConfig = this.reflector.getAllAndOverride<{
      permissions: number[];
      requireAll: boolean;
    }>(PERMISSIONS_KEY, [context.getHandler(), context.getClass()]);

    if (!permissionConfig) {
      return true; // 권한 요구사항이 없으면 통과
    }

    const request = context.switchToHttp().getRequest<RequestWithUser>();
    const user = request.user;

    if (!user || user.permissions === undefined || user.permissions === null) {
      throw new ForbiddenException('권한 정보가 없습니다.');
    }

    // permissions가 string인 경우 number로 변환
    let userPermissions: number;
    if (typeof user.permissions === 'string') {
      userPermissions = parseInt(user.permissions, 10);
    } else if (typeof user.permissions === 'bigint') {
      userPermissions = Number(user.permissions);
    } else {
      userPermissions = user.permissions;
    }

    if (typeof userPermissions !== 'number' || isNaN(userPermissions)) {
      throw new ForbiddenException('권한 정보가 올바르지 않습니다.');
    }

    // ADMIN 권한이 있는 경우 모든 권한 체크 통과
    if (PermissionUtils.isAdmin(userPermissions)) {
      return true;
    }

    const { permissions, requireAll } = permissionConfig;
    const hasPermission = requireAll
      ? PermissionUtils.hasAllPermissions(userPermissions, permissions)
      : PermissionUtils.hasAnyPermission(userPermissions, permissions);

    if (!hasPermission) {
      throw new ForbiddenException('필요한 권한이 없습니다.');
    }

    return true;
  }
}
