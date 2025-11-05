import {
  Injectable,
  UnauthorizedException,
  BadRequestException,
  ConflictException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';
import { User } from '../auth/user.entity';
import { UserManagementService } from '../auth/services/user-management.service';
import { CacheManagerService } from '../cache/cache-manager.service';
import { CACHE_CONFIG, CACHE_KEYS } from '../constants/cache.constants';
import { AUTH_CONSTANTS } from '../constants/auth.constants';
import { VALIDATION_CONSTANTS } from '../constants/validation.constants';

export type SensitiveUserFields =
  | 'password'
  | 'twoFactorSecret'
  | 'backupCodes';

export type UpdatableUserFields =
  | 'firstName'
  | 'lastName'
  | 'username'
  | 'bio'
  | 'website'
  | 'location';

@Injectable()
export class ProfileService {
  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
    private userManagementService: UserManagementService,
    private cacheManagerService: CacheManagerService,
  ) {}

  /**
   * Convert database tinyint values (0/1) to proper boolean values
   */
  private convertUserBooleans(user: User): User {
    return {
      ...user,
      isEmailVerified: Boolean(user.isEmailVerified),
      isTwoFactorEnabled: Boolean(user.isTwoFactorEnabled),
      isActive: Boolean(user.isActive),
    };
  }

  async findById(id: number): Promise<User> {
    const cacheKey = CACHE_KEYS.profile.user(id);

    // Get from cache first
    const cached = await this.cacheManagerService.getCacheValue<User>(cacheKey);
    if (cached) {
      // Convert cached boolean values
      return this.convertUserBooleans(cached);
    }

    // If not in cache, query the DB
    const user = await this.userRepository.findOne({ where: { id } });

    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    // Convert boolean values before caching and returning
    const userWithBooleans = this.convertUserBooleans(user);

    // Store in cache
    await this.cacheManagerService.setCacheValue(
      cacheKey,
      userWithBooleans,
      CACHE_CONFIG.TTL.USER_PROFILE,
    );
    return userWithBooleans;
  }

  async findSafeById(id: number): Promise<Omit<User, SensitiveUserFields>> {
    const user = await this.findById(id);

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { password, twoFactorSecret, backupCodes, ...safeUser } = user;

    return safeUser as Omit<User, SensitiveUserFields>;
  }

  async updateProfile(
    userId: number,
    updateData: Partial<User>,
  ): Promise<User> {
    const user = await this.userRepository.findOne({ where: { id: userId } });

    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    // Filter only updatable fields
    const allowedFields = [
      'firstName',
      'lastName',
      'username',
      'bio',
      'website',
      'location',
    ] as const;
    const filteredData: Partial<Pick<User, UpdatableUserFields>> = {};

    // Helper function to safely assign values
    const safeAssign = (
      key: keyof typeof filteredData,
      value: string | undefined,
    ) => {
      if (key === 'firstName') filteredData.firstName = value as string;
      else if (key === 'lastName') filteredData.lastName = value as string;
      else if (key === 'username') filteredData.username = value as string;
      else if (key === 'bio') filteredData.bio = value;
      else if (key === 'website') filteredData.website = value;
      else if (key === 'location') filteredData.location = value;
    };

    // Validate and assign fields
    for (const field of allowedFields) {
      if (
        Object.prototype.hasOwnProperty.call(updateData, field) &&
        // eslint-disable-next-line security/detect-object-injection
        updateData[field] !== undefined
      ) {
        // Safe property access
        const value =
          field === 'firstName'
            ? updateData.firstName
            : field === 'lastName'
              ? updateData.lastName
              : field === 'username'
                ? updateData.username
                : field === 'bio'
                  ? updateData.bio
                  : field === 'website'
                    ? updateData.website
                    : field === 'location'
                      ? updateData.location
                      : undefined;

        // Field-specific validations
        if (field === 'username') {
          if (typeof value !== 'string' || value.trim().length === 0) {
            throw new BadRequestException('사용자명은 비어있을 수 없습니다.');
          }
          if (value.length < 3) {
            throw new BadRequestException(
              '사용자명은 최소 3자 이상이어야 합니다.',
            );
          }
          if (value.length > 100) {
            throw new BadRequestException(
              '사용자명은 최대 100자까지 가능합니다.',
            );
          }
          if (!VALIDATION_CONSTANTS.PROFILE_USERNAME.REGEX.test(value)) {
            throw new BadRequestException(
              VALIDATION_CONSTANTS.PROFILE_USERNAME.ERROR_MESSAGES.INVALID_FORMAT,
            );
          }

          // Check for username uniqueness
          const existingUser = await this.userRepository.findOne({
            where: { username: value.trim() },
          });
          if (existingUser && existingUser.id !== userId) {
            throw new ConflictException('이미 사용중인 사용자명입니다.');
          }

          safeAssign(field, value.trim());
        } else if (field === 'firstName' || field === 'lastName') {
          if (value !== null && value !== undefined) {
            if (typeof value !== 'string') {
              throw new BadRequestException(
                `${field === 'firstName' ? '이름' : '성'}은 문자열이어야 합니다.`,
              );
            }
            const trimmedValue = value.trim();
            if (trimmedValue.length === 0) {
              throw new BadRequestException(
                `${field === 'firstName' ? '이름' : '성'}은 비어있을 수 없습니다.`,
              );
            }
            if (trimmedValue.length > 100) {
              throw new BadRequestException(
                `${field === 'firstName' ? '이름' : '성'}은 최대 100자까지 가능합니다.`,
              );
            }
            // Limit special characters (allow basic letters, spaces, hyphens)
            if (!VALIDATION_CONSTANTS.NAME.REGEX.test(trimmedValue)) {
              throw new BadRequestException(
                VALIDATION_CONSTANTS.NAME.ERROR_MESSAGES.INVALID_FORMAT,
              );
            }
            safeAssign(field, trimmedValue);
          }
        } else if (field === 'bio') {
          if (value !== null && value !== undefined) {
            if (typeof value !== 'string') {
              throw new BadRequestException('소개글은 문자열이어야 합니다.');
            }
            if (value.length > 500) {
              throw new BadRequestException(
                '소개글은 최대 500자까지 가능합니다.',
              );
            }
            safeAssign(field, value.trim() || undefined);
          } else {
            safeAssign(field, undefined);
          }
        } else if (field === 'website') {
          if (value !== null && value !== undefined) {
            if (typeof value !== 'string') {
              throw new BadRequestException('웹사이트는 문자열이어야 합니다.');
            }
            const trimmedValue = value.trim();
            if (trimmedValue && trimmedValue.length > 0) {
              // Validate URL format
              try {
                new URL(trimmedValue);
              } catch {
                throw new BadRequestException(
                  '올바른 URL 형식이 아닙니다. (예: https://example.com)',
                );
              }
              if (trimmedValue.length > 255) {
                throw new BadRequestException(
                  '웹사이트 URL은 최대 255자까지 가능합니다.',
                );
              }
              safeAssign(field, trimmedValue);
            } else {
              safeAssign(field, undefined);
            }
          } else {
            safeAssign(field, undefined);
          }
        } else if (field === 'location') {
          if (value !== null && value !== undefined) {
            if (typeof value !== 'string') {
              throw new BadRequestException('지역은 문자열이어야 합니다.');
            }
            if (value.length > 100) {
              throw new BadRequestException(
                '지역은 최대 100자까지 가능합니다.',
              );
            }
            safeAssign(field, value.trim() || undefined);
          } else {
            safeAssign(field, undefined);
          }
        }
      }
    }

    // Check if there is any data to update
    if (Object.keys(filteredData).length === 0) {
      throw new BadRequestException('업데이트할 데이터가 없습니다.');
    }

    // Update the database
    await this.userRepository.update(userId, filteredData);

    // Invalidate cache
    await this.cacheManagerService.invalidateAllUserCache(userId);

    // Retrieve updated user information
    const updatedUser = await this.userRepository.findOne({
      where: { id: userId },
    });

    if (!updatedUser) {
      throw new UnauthorizedException('User not found after update');
    }

    // Convert 0/1 values to proper booleans
    return this.convertUserBooleans(updatedUser);
  }

  async changePassword(
    userId: number,
    currentPassword: string,
    newPassword: string,
  ): Promise<void> {
    const user = await this.userRepository.findOne({ where: { id: userId } });

    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    // Validate current password
    const isCurrentPasswordValid = await bcrypt.compare(
      currentPassword,
      user.password,
    );
    if (!isCurrentPasswordValid) {
      throw new BadRequestException('현재 비밀번호가 일치하지 않습니다.');
    }

    // Validate new password
    if (newPassword.length < 8) {
      throw new BadRequestException('비밀번호는 최소 8자 이상이어야 합니다.');
    }

    // Hash new password
    const hashedNewPassword = await bcrypt.hash(
      newPassword,
      AUTH_CONSTANTS.BCRYPT_SALT_ROUNDS,
    );

    // Update password
    await this.userRepository.update(userId, { password: hashedNewPassword });

    // Invalidate cache (also invalidate user info cache when password changes)
    await this.cacheManagerService.invalidateAllUserCache(userId);
  }

  async checkUsernameAvailability(
    username: string,
    excludeUserId?: number,
  ): Promise<{ available: boolean; message: string }> {
    // Validate input
    if (username?.trim().length === 0) {
      return { available: false, message: '사용자명을 입력해주세요.' };
    }

    const trimmedUsername = username.trim();

    // Validate length
    if (trimmedUsername.length < 3) {
      return {
        available: false,
        message: '사용자명은 최소 3자 이상이어야 합니다.',
      };
    }

    if (trimmedUsername.length > 100) {
      return {
        available: false,
        message: '사용자명은 최대 100자까지 가능합니다.',
      };
    }

    // Validate format
    if (!VALIDATION_CONSTANTS.PROFILE_USERNAME.REGEX.test(trimmedUsername)) {
      return {
        available: false,
        message:
          VALIDATION_CONSTANTS.PROFILE_USERNAME.ERROR_MESSAGES.INVALID_FORMAT,
      };
    }

    // Check for username uniqueness
    const existingUser = await this.userRepository.findOne({
      where: { username: trimmedUsername },
    });

    if (existingUser && existingUser.id !== excludeUserId) {
      return { available: false, message: '이미 사용중인 사용자명입니다.' };
    }

    return { available: true, message: '사용 가능한 사용자명입니다.' };
  }

  async uploadAvatar(
    userId: number,
    file: Express.Multer.File,
  ): Promise<string> {
    const avatarUrl = await this.userManagementService.uploadAvatar(
      userId,
      file,
    );

    // Invalidate cache when avatar changes
    await this.cacheManagerService.invalidateAllUserCache(userId);

    return avatarUrl;
  }

  async removeAvatar(userId: number): Promise<void> {
    await this.userManagementService.removeAvatar(userId);

    // Invalidate cache when avatar is removed
    await this.cacheManagerService.invalidateAllUserCache(userId);
  }
}
