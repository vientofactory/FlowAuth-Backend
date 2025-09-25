import { PermissionUtils } from '../utils/permission.util';
import { PERMISSIONS } from '../constants/auth.constants';

describe('PermissionUtils', () => {
  describe('hasPermission', () => {
    it('should return true when user has the required permission', () => {
      const userPermissions = PERMISSIONS.READ_USER;
      const requiredPermission = PERMISSIONS.READ_USER;

      const result = PermissionUtils.hasPermission(
        userPermissions,
        requiredPermission,
      );

      expect(result).toBe(true);
    });

    it('should return false when user does not have the required permission', () => {
      const userPermissions = PERMISSIONS.WRITE_USER;
      const requiredPermission = PERMISSIONS.READ_USER;

      const result = PermissionUtils.hasPermission(
        userPermissions,
        requiredPermission,
      );

      expect(result).toBe(false);
    });

    it('should return true when user has multiple permissions including the required one', () => {
      const userPermissions = PERMISSIONS.READ_USER | PERMISSIONS.WRITE_USER;
      const requiredPermission = PERMISSIONS.READ_USER;

      const result = PermissionUtils.hasPermission(
        userPermissions,
        requiredPermission,
      );

      expect(result).toBe(true);
    });
  });

  describe('hasAnyPermission', () => {
    it('should return true when user has at least one of the required permissions', () => {
      const userPermissions = PERMISSIONS.READ_USER;
      const requiredPermissions = [
        PERMISSIONS.READ_USER,
        PERMISSIONS.WRITE_USER,
      ];

      const result = PermissionUtils.hasAnyPermission(
        userPermissions,
        requiredPermissions,
      );

      expect(result).toBe(true);
    });

    it('should return false when user has none of the required permissions', () => {
      const userPermissions = PERMISSIONS.DELETE_USER;
      const requiredPermissions = [
        PERMISSIONS.READ_USER,
        PERMISSIONS.WRITE_USER,
      ];

      const result = PermissionUtils.hasAnyPermission(
        userPermissions,
        requiredPermissions,
      );

      expect(result).toBe(false);
    });
  });

  describe('hasAllPermissions', () => {
    it('should return true when user has all required permissions', () => {
      const userPermissions = PERMISSIONS.READ_USER | PERMISSIONS.WRITE_USER;
      const requiredPermissions = [
        PERMISSIONS.READ_USER,
        PERMISSIONS.WRITE_USER,
      ];

      const result = PermissionUtils.hasAllPermissions(
        userPermissions,
        requiredPermissions,
      );

      expect(result).toBe(true);
    });

    it('should return false when user is missing at least one required permission', () => {
      const userPermissions = PERMISSIONS.READ_USER;
      const requiredPermissions = [
        PERMISSIONS.READ_USER,
        PERMISSIONS.WRITE_USER,
      ];

      const result = PermissionUtils.hasAllPermissions(
        userPermissions,
        requiredPermissions,
      );

      expect(result).toBe(false);
    });
  });
});
