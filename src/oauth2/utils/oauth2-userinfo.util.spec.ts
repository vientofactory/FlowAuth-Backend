import {
  OAuth2UserInfoBuilder,
  buildOAuth2UserInfo,
  ScopeFieldMapping,
} from './oauth2-userinfo.util';
import { User } from '../../auth/user.entity';
import { USER_TYPES, PERMISSIONS } from '../../constants/auth.constants';

describe('OAuth2UserInfoBuilder', () => {
  let mockUser: User;

  beforeEach(() => {
    const now = new Date();
    mockUser = {
      id: 1,
      username: 'testuser',
      email: 'test@example.com',
      password: 'hashedpassword',
      firstName: undefined,
      lastName: undefined,
      userType: USER_TYPES.REGULAR,
      isEmailVerified: false,
      permissions: PERMISSIONS.READ_USER | PERMISSIONS.READ_DASHBOARD, // 일반 사용자 권한
      lastLoginAt: undefined,
      twoFactorSecret: undefined,
      isTwoFactorEnabled: false,
      backupCodes: undefined,
      isActive: true,
      avatar: undefined,
      bio: undefined,
      website: undefined,
      location: undefined,
      createdAt: now,
      updatedAt: now,
    };
  });

  describe('buildUserInfo', () => {
    it('should return only sub when no scopes provided', () => {
      const result = OAuth2UserInfoBuilder.buildUserInfo(mockUser, []);

      expect(result).toEqual({
        sub: '1',
      });
    });

    it('should include email when email scope is provided', () => {
      const result = OAuth2UserInfoBuilder.buildUserInfo(mockUser, ['email']);

      expect(result).toEqual({
        sub: '1',
        email: 'test@example.com',
      });
    });

    it('should include username and roles when identify scope is provided', () => {
      const result = OAuth2UserInfoBuilder.buildUserInfo(mockUser, [
        'identify',
      ]);

      expect(result).toEqual({
        sub: '1',
        username: 'testuser',
        roles: ['일반 사용자'], // PermissionUtils.getRoleName(1)의 결과
      });
    });

    it('should include all fields when both scopes are provided', () => {
      const result = OAuth2UserInfoBuilder.buildUserInfo(mockUser, [
        'email',
        'identify',
      ]);

      expect(result).toEqual({
        sub: '1',
        email: 'test@example.com',
        username: 'testuser',
        roles: ['일반 사용자'],
      });
    });

    it('should handle unsupported scopes gracefully', () => {
      const result = OAuth2UserInfoBuilder.buildUserInfo(mockUser, [
        'unsupported',
        'email',
      ]);

      expect(result).toEqual({
        sub: '1',
        email: 'test@example.com',
      });
    });
  });

  describe('isScopeSupported', () => {
    it('should return true for supported scopes', () => {
      expect(OAuth2UserInfoBuilder.isScopeSupported('email')).toBe(true);
      expect(OAuth2UserInfoBuilder.isScopeSupported('identify')).toBe(true);
    });

    it('should return false for unsupported scopes', () => {
      expect(OAuth2UserInfoBuilder.isScopeSupported('unsupported')).toBe(false);
      expect(OAuth2UserInfoBuilder.isScopeSupported('profile')).toBe(false);
    });
  });

  describe('getSupportedScopes', () => {
    it('should return all supported scopes', () => {
      const scopes = OAuth2UserInfoBuilder.getSupportedScopes();

      expect(scopes).toContain('email');
      expect(scopes).toContain('identify');
      expect(scopes).toHaveLength(2);
    });
  });

  describe('getFieldsForScope', () => {
    it('should return fields for email scope', () => {
      const fields = OAuth2UserInfoBuilder.getFieldsForScope('email');

      expect(fields).toEqual(['email']);
    });

    it('should return fields for identify scope', () => {
      const fields = OAuth2UserInfoBuilder.getFieldsForScope('identify');

      expect(fields).toEqual(['username', 'roles']);
    });

    it('should return empty array for unsupported scope', () => {
      const fields = OAuth2UserInfoBuilder.getFieldsForScope('unsupported');

      expect(fields).toEqual([]);
    });
  });

  describe('registerScopeMapping', () => {
    it('should register new scope mapping', () => {
      const newMapping: ScopeFieldMapping = {
        scope: 'profile',
        fields: ['email', 'username'],
        fieldMapper: (user: User) => ({
          email: user.email,
          username: user.username,
        }),
      };

      OAuth2UserInfoBuilder.registerScopeMapping(newMapping);

      expect(OAuth2UserInfoBuilder.isScopeSupported('profile')).toBe(true);
      expect(OAuth2UserInfoBuilder.getFieldsForScope('profile')).toEqual([
        'email',
        'username',
      ]);
    });

    it('should throw error when registering duplicate scope', () => {
      const duplicateMapping: ScopeFieldMapping = {
        scope: 'email',
        fields: ['email'],
        fieldMapper: (user: User) => ({ email: user.email }),
      };

      expect(() => {
        OAuth2UserInfoBuilder.registerScopeMapping(duplicateMapping);
      }).toThrow("Scope 'email' is already registered");
    });
  });
});

describe('buildOAuth2UserInfo', () => {
  it('should delegate to OAuth2UserInfoBuilder.buildUserInfo', () => {
    const now = new Date();
    const mockUser: User = {
      id: 1,
      email: 'test@example.com',
      username: 'testuser',
      password: 'hashedpassword',
      firstName: undefined,
      lastName: undefined,
      userType: USER_TYPES.REGULAR,
      isEmailVerified: false,
      permissions: 1,
      lastLoginAt: undefined,
      twoFactorSecret: undefined,
      isTwoFactorEnabled: false,
      backupCodes: undefined,
      isActive: true,
      avatar: undefined,
      bio: undefined,
      website: undefined,
      location: undefined,
      createdAt: now,
      updatedAt: now,
    };
    const scopes = ['email'];

    const result = buildOAuth2UserInfo(mockUser, scopes);

    expect(result).toEqual({
      sub: '1',
      email: 'test@example.com',
    });
  });
});
