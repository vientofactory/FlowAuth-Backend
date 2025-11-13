import {
  OAuth2UserInfoBuilder,
  buildOAuth2UserInfo,
  ScopeFieldMapping,
} from './oauth2-userinfo.util';
import { User } from '../../auth/user.entity';
import { USER_TYPES, PERMISSIONS } from '@flowauth/shared';
import { ConfigService } from '@nestjs/config';

describe('OAuth2UserInfoBuilder', () => {
  let mockUser: User;
  let mockConfigService: ConfigService;

  beforeEach(() => {
    mockConfigService = {
      get: jest.fn().mockReturnValue('http://localhost:3000'),
    } as any;
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

  describe('buildUserInfoWithConfig', () => {
    it('should return only sub when no scopes provided', () => {
      const result = OAuth2UserInfoBuilder.buildUserInfoWithConfig(
        mockUser,
        [],
        mockConfigService,
      );

      expect(result).toEqual({
        sub: '1',
      });
    });

    it('should include email when email scope is provided', () => {
      const result = OAuth2UserInfoBuilder.buildUserInfoWithConfig(
        mockUser,
        ['email'],
        mockConfigService,
      );

      expect(result).toEqual({
        sub: '1',
        email: 'test@example.com',
        email_verified: false,
      });
    });

    it('should include username and roles when identify scope is provided', () => {
      const result = OAuth2UserInfoBuilder.buildUserInfoWithConfig(
        mockUser,
        ['identify'],
        mockConfigService,
      );

      expect(result).toEqual({
        sub: '1',
        preferred_username: 'testuser',
        roles: ['사용자 정의'], // PermissionUtils.getRoleName(1)의 실제 결과
      });
    });

    it('should include all fields when both scopes are provided', () => {
      const result = OAuth2UserInfoBuilder.buildUserInfoWithConfig(
        mockUser,
        ['email', 'identify'],
        mockConfigService,
      );

      expect(result).toEqual({
        sub: '1',
        email: 'test@example.com',
        email_verified: false,
        preferred_username: 'testuser',
        roles: ['사용자 정의'],
      });
    });

    it('should handle unsupported scopes gracefully', () => {
      const result = OAuth2UserInfoBuilder.buildUserInfoWithConfig(
        mockUser,
        ['email', 'unsupported'],
        mockConfigService,
      );

      expect(result).toEqual({
        sub: '1',
        email: 'test@example.com',
        email_verified: false,
      });
    });
  });

  describe('isScopeSupported', () => {
    it('should return true for supported scopes', () => {
      expect(OAuth2UserInfoBuilder.isScopeSupported('email')).toBe(true);
      expect(OAuth2UserInfoBuilder.isScopeSupported('identify')).toBe(true);
      expect(OAuth2UserInfoBuilder.isScopeSupported('profile')).toBe(true);
    });

    it('should return false for unsupported scopes', () => {
      expect(OAuth2UserInfoBuilder.isScopeSupported('unsupported')).toBe(false);
      expect(OAuth2UserInfoBuilder.isScopeSupported('invalid')).toBe(false);
    });
  });

  describe('getSupportedScopes', () => {
    it('should return all supported scopes', () => {
      const scopes = OAuth2UserInfoBuilder.getSupportedScopes();

      expect(scopes).toContain('email');
      expect(scopes).toContain('identify');
      expect(scopes).toContain('profile');
      expect(scopes).toHaveLength(3);
    });
  });

  describe('getFieldsForScope', () => {
    it('should return fields for email scope', () => {
      const fields = OAuth2UserInfoBuilder.getFieldsForScope('email');

      expect(fields).toEqual(['email', 'email_verified']);
    });

    it('should return fields for identify scope', () => {
      const fields = OAuth2UserInfoBuilder.getFieldsForScope('identify');

      expect(fields).toEqual(['preferred_username', 'roles']);
    });

    it('should return empty array for unsupported scope', () => {
      const fields = OAuth2UserInfoBuilder.getFieldsForScope('unsupported');

      expect(fields).toEqual([]);
    });
  });

  describe('registerScopeMapping', () => {
    it('should register new scope mapping', () => {
      const newMapping: ScopeFieldMapping = {
        scope: 'custom',
        fields: ['email', 'preferred_username'],
        fieldMapper: (user: User) => ({
          email: user.email,
          preferred_username: user.username,
        }),
      };

      OAuth2UserInfoBuilder.registerScopeMapping(newMapping);

      expect(OAuth2UserInfoBuilder.isScopeSupported('custom')).toBe(true);
      expect(OAuth2UserInfoBuilder.getFieldsForScope('custom')).toEqual([
        'email',
        'preferred_username',
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
  it('should delegate to OAuth2UserInfoBuilder.buildUserInfoWithConfig', () => {
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
    const mockConfigService = {
      get: jest.fn().mockReturnValue('http://localhost:3000'),
    } as any;

    const result = buildOAuth2UserInfo(mockUser, scopes, mockConfigService);

    expect(result).toEqual({
      sub: '1',
      email: 'test@example.com',
      email_verified: false,
    });
  });
});
