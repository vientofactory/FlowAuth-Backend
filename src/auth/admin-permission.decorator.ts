import { SetMetadata } from '@nestjs/common';
import { PERMISSIONS } from '@flowauth/shared';
import { PERMISSIONS_KEY } from './permissions.guard';

export const RequireAdminPermission = () =>
  SetMetadata(PERMISSIONS_KEY, {
    permissions: [PERMISSIONS.ADMIN_ACCESS],
    requireAll: false,
  });
