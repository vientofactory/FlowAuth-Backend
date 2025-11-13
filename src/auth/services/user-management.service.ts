import {
  Injectable,
  UnauthorizedException,
  BadRequestException,
  Logger,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';
import { User } from '../user.entity';
import { Client } from '../../oauth2/client.entity';
import { Token } from '../../oauth2/token.entity';
import { MoreThan } from 'typeorm';
import { AUTH_CONSTANTS } from '@flowauth/shared';
import { CACHE_CONFIG } from '../../constants/cache.constants';
import { TwoFactorService } from '../two-factor.service';
import { FileUploadService } from '../../upload/file-upload.service';
import { RecaptchaService } from '../../utils/recaptcha.util';
import { CacheManagerService } from '../../cache/cache-manager.service';

@Injectable()
export class UserManagementService {
  private readonly logger = new Logger(UserManagementService.name);

  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
    @InjectRepository(Client)
    private clientRepository: Repository<Client>,
    @InjectRepository(Token)
    private tokenRepository: Repository<Token>,
    private twoFactorService: TwoFactorService,
    private fileUploadService: FileUploadService,
    private recaptchaService: RecaptchaService,
    private cacheManagerService: CacheManagerService,
  ) {}

  async findById(id: number): Promise<User> {
    const cacheKey = `user:${id}`;

    // Try cache first
    const cached = await this.cacheManagerService.getCacheValue<User>(cacheKey);
    if (cached) {
      return cached;
    }

    // Fetch from database
    const user = await this.userRepository.findOne({
      where: { id, isActive: true },
    });

    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    // Cache the result
    await this.cacheManagerService.setCacheValue(
      cacheKey,
      user,
      CACHE_CONFIG.TTL.USER_PROFILE,
    );
    return user;
  }

  async findByUsername(username: string): Promise<User | null> {
    return this.userRepository.findOne({
      where: { username, isActive: true },
    });
  }

  async findByEmail(email: string): Promise<User | null> {
    return this.userRepository.findOne({
      where: { email, isActive: true },
    });
  }

  async updateProfile(
    userId: number,
    updateData: Partial<User>,
  ): Promise<User> {
    // Use transaction with optimistic locking to prevent race conditions
    const dataSource = this.userRepository.manager.connection;

    return await dataSource.transaction(async (manager) => {
      // Fetch user with pessimistic lock to prevent concurrent updates
      const user = await manager.findOne(User, {
        where: { id: userId, isActive: true },
        lock: { mode: 'pessimistic_write' },
      });

      if (!user) {
        throw new UnauthorizedException('User not found');
      }

      // Safe field assignment to prevent object injection
      if (updateData.firstName !== undefined)
        user.firstName = updateData.firstName;
      if (updateData.lastName !== undefined)
        user.lastName = updateData.lastName;
      if (updateData.username !== undefined)
        user.username = updateData.username;
      if (updateData.email !== undefined) user.email = updateData.email;
      if (updateData.userType !== undefined)
        user.userType = updateData.userType;
      if (updateData.avatar !== undefined) user.avatar = updateData.avatar;
      if (updateData.bio !== undefined) user.bio = updateData.bio;
      if (updateData.website !== undefined) user.website = updateData.website;
      if (updateData.location !== undefined)
        user.location = updateData.location;

      // Handle password update separately
      if (updateData.password) {
        user.password = await bcrypt.hash(
          updateData.password,
          AUTH_CONSTANTS.BCRYPT_SALT_ROUNDS,
        );
      }

      const savedUser = await manager.save(user);

      // Clear cache after successful transaction
      await this.cacheManagerService.delCacheKey(`user:${userId}`);

      this.logger.log(`User profile updated: ${user.username}`);
      return savedUser;
    });
  }

  async updateLastLogin(userId: number): Promise<void> {
    await this.userRepository.update(userId, {
      lastLoginAt: new Date(),
    });

    // Clear cache
    await this.cacheManagerService.delCacheKey(`user:${userId}`);
  }

  async enableTwoFactor(
    userId: number,
  ): Promise<{ secret: string; qrCodeUrl: string }> {
    const dataSource = this.userRepository.manager.connection;

    return await dataSource.transaction(async (manager) => {
      const user = await manager.findOne(User, {
        where: { id: userId, isActive: true },
        lock: { mode: 'pessimistic_write' },
      });

      if (!user) {
        throw new UnauthorizedException('User not found');
      }

      if (user.isTwoFactorEnabled) {
        throw new BadRequestException('2FA is already enabled');
      }

      const { secret, qrCodeUrl } =
        await this.twoFactorService.generateSecret(userId);

      // Update user (don't enable yet, wait for verification) within transaction
      await manager.update(User, userId, {
        twoFactorSecret: secret,
      });

      // Clear cache after successful transaction
      await this.cacheManagerService.delCacheKey(`user:${userId}`);

      return { secret, qrCodeUrl };
    });
  }

  async verifyAndEnableTwoFactor(userId: number, token: string): Promise<void> {
    const dataSource = this.userRepository.manager.connection;

    await dataSource.transaction(async (manager) => {
      const user = await manager.findOne(User, {
        where: { id: userId, isActive: true },
        lock: { mode: 'pessimistic_write' },
      });

      if (!user) {
        throw new UnauthorizedException('User not found');
      }

      if (!user.twoFactorSecret) {
        throw new BadRequestException('2FA setup not initiated');
      }

      const isValid = await this.twoFactorService.verifyToken(userId, token);
      if (!isValid) {
        throw new BadRequestException('Invalid 2FA token');
      }

      // Enable 2FA within transaction
      await manager.update(User, userId, {
        isTwoFactorEnabled: true,
      });

      // Clear cache after successful transaction
      await this.cacheManagerService.delCacheKey(`user:${userId}`);

      this.logger.log(`2FA enabled for user: ${user.username}`);
    });
  }

  async disableTwoFactor(userId: number): Promise<void> {
    const dataSource = this.userRepository.manager.connection;

    await dataSource.transaction(async (manager) => {
      const user = await manager.findOne(User, {
        where: { id: userId, isActive: true },
        lock: { mode: 'pessimistic_write' },
      });

      if (!user) {
        throw new UnauthorizedException('User not found');
      }

      await manager.getRepository(User).update(userId, {
        isTwoFactorEnabled: false,
        twoFactorSecret: null,
        backupCodes: null,
      });

      // Clear cache after successful transaction
      await this.cacheManagerService.delCacheKey(`user:${userId}`);

      this.logger.log(`2FA disabled for user: ${user.username}`);
    });
  }

  async uploadAvatar(
    userId: number,
    file: Express.Multer.File,
  ): Promise<string> {
    const dataSource = this.userRepository.manager.connection;

    return await dataSource.transaction(async (manager) => {
      const user = await manager.findOne(User, {
        where: { id: userId, isActive: true },
        lock: { mode: 'pessimistic_write' },
      });

      if (!user) {
        throw new UnauthorizedException('User not found');
      }

      const oldAvatarUrl = user.avatar;

      // Process avatar image with Sharp for optimization first
      const avatarUrl = await this.fileUploadService.processAvatarImage(
        userId,
        file,
      );

      // Update user with new avatar URL within transaction
      await manager.update(User, userId, { avatar: avatarUrl });

      // Delete existing avatar after successful database update
      if (oldAvatarUrl) {
        try {
          const deleted = this.fileUploadService.deleteFile(oldAvatarUrl);
          if (deleted) {
            this.logger.log(`Deleted existing avatar for user ${userId}`);
          }
        } catch (error) {
          // Log but don't fail the upload if old file deletion fails
          this.logger.warn(
            `Failed to delete existing avatar for user ${userId}: ${error instanceof Error ? error.message : String(error)}`,
          );
        }
      }

      // Clear cache after successful transaction
      await this.cacheManagerService.delCacheKey(`user:${userId}`);

      this.logger.log(`Avatar uploaded for user: ${user.username}`);
      return avatarUrl;
    });
  }

  async removeAvatar(userId: number): Promise<void> {
    const user = await this.findById(userId);

    if (!user.avatar) {
      throw new BadRequestException('사용자에게 아바타가 없습니다.');
    }

    // Delete avatar file from storage
    const deleted = this.fileUploadService.deleteFile(user.avatar);
    if (!deleted) {
      this.logger.warn(
        `Failed to delete avatar file for user ${userId}: ${user.avatar}`,
      );
    }

    // Update user to remove avatar URL
    user.avatar = null;
    await this.userRepository.save(user);

    // Clear cache
    await this.cacheManagerService.delCacheKey(`user:${userId}`);

    this.logger.log(`Avatar removed for user: ${user.username}`);
  }

  async deleteUser(userId: number): Promise<void> {
    const user = await this.findById(userId);

    // Soft delete - mark as inactive instead of hard delete
    await this.userRepository.update(userId, { isActive: false });

    // Clear cache
    await this.cacheManagerService.delCacheKey(`user:${userId}`);

    this.logger.log(`User deactivated: ${user.username}`);
  }

  async getUserStats(userId: number): Promise<{
    totalClients: number;
    activeTokens: number;
    lastLogin: Date | null;
  }> {
    const user = await this.findById(userId);

    // Count user's OAuth2 clients
    const totalClients = await this.clientRepository.count({
      where: { userId },
    });

    // Count active tokens for user (not revoked and not expired)
    const activeTokens = await this.tokenRepository.count({
      where: {
        user: { id: userId },
        isRevoked: false,
        expiresAt: MoreThan(new Date()),
      },
    });

    return {
      totalClients,
      activeTokens,
      lastLogin: user.lastLoginAt ?? null,
    };
  }
}
