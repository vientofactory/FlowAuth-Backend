import {
  Injectable,
  ConflictException,
  UnauthorizedException,
  BadRequestException,
  Logger,
  Inject,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import type { Cache } from 'cache-manager';
import * as bcrypt from 'bcrypt';
import { User } from '../user.entity';
import { CreateUserDto } from '../dto/create-user.dto';
import {
  AUTH_CONSTANTS,
  AUTH_ERROR_MESSAGES,
  USER_TYPES,
  USER_TYPE_PERMISSIONS,
  PERMISSION_UTILS,
  CACHE_CONSTANTS,
} from '../../constants/auth.constants';
import { TwoFactorService } from '../two-factor.service';
import { FileUploadService } from '../../upload/file-upload.service';
import { RecaptchaService } from '../../utils/recaptcha.util';

@Injectable()
export class UserManagementService {
  private readonly logger = new Logger(UserManagementService.name);

  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
    private twoFactorService: TwoFactorService,
    private fileUploadService: FileUploadService,
    private recaptchaService: RecaptchaService,
    @Inject(CACHE_MANAGER)
    private cacheManager: Cache,
  ) {}

  async register(createUserDto: CreateUserDto): Promise<User> {
    const {
      username,
      email,
      password,
      firstName,
      lastName,
      userType,
      recaptchaToken,
    } = createUserDto;

    // Verify reCAPTCHA token (required for registration)
    const isValidRecaptcha = await this.recaptchaService.verifyToken(
      recaptchaToken,
      'register',
    );
    if (!isValidRecaptcha) {
      throw new UnauthorizedException('reCAPTCHA verification failed');
    }

    // Check if user already exists
    const existingUser = await this.userRepository.findOne({
      where: [{ username }, { email }],
    });

    if (existingUser) {
      if (existingUser.email === email) {
        throw new ConflictException('이미 사용중인 이메일입니다.');
      }
      if (existingUser.username === username) {
        throw new ConflictException('이미 사용중인 사용자명입니다.');
      }
      throw new ConflictException(AUTH_ERROR_MESSAGES.USER_ALREADY_EXISTS);
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(
      password,
      AUTH_CONSTANTS.BCRYPT_SALT_ROUNDS,
    );

    // Check if this is the first user (should get admin permissions)
    const userCount = await this.userRepository.count();
    const isFirstUser = userCount === 0;

    let permissions =
      USER_TYPE_PERMISSIONS[userType as USER_TYPES] ||
      USER_TYPE_PERMISSIONS[USER_TYPES.REGULAR];

    if (isFirstUser) {
      // First user gets admin permissions
      permissions = PERMISSION_UTILS.getAllPermissionsMask();
    }

    // Create user
    const user = this.userRepository.create({
      username,
      email,
      password: hashedPassword,
      firstName,
      lastName,
      permissions,
      userType,
      isEmailVerified: false,
      isTwoFactorEnabled: false,
      isActive: true,
    });

    const savedUser = await this.userRepository.save(user);

    // Clear user cache
    await this.cacheManager.del(`user:${savedUser.id}`);

    this.logger.log(`User registered: ${username} (${email})`);
    return savedUser;
  }

  async findById(id: number): Promise<User> {
    const cacheKey = `user:${id}`;

    // Try cache first
    const cached = await this.cacheManager.get<User>(cacheKey);
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
    await this.cacheManager.set(cacheKey, user, CACHE_CONSTANTS.USER_CACHE_TTL);
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
    const user = await this.findById(userId);
    // Safe field assignment to prevent object injection
    if (updateData.firstName !== undefined)
      user.firstName = updateData.firstName;
    if (updateData.lastName !== undefined) user.lastName = updateData.lastName;
    if (updateData.username !== undefined) user.username = updateData.username;
    if (updateData.email !== undefined) user.email = updateData.email;
    if (updateData.userType !== undefined) user.userType = updateData.userType;
    if (updateData.avatar !== undefined) user.avatar = updateData.avatar;
    if (updateData.bio !== undefined) user.bio = updateData.bio;
    if (updateData.website !== undefined) user.website = updateData.website;
    if (updateData.location !== undefined) user.location = updateData.location;

    // Handle password update separately
    if (updateData.password) {
      user.password = await bcrypt.hash(
        updateData.password,
        AUTH_CONSTANTS.BCRYPT_SALT_ROUNDS,
      );
    }

    const savedUser = await this.userRepository.save(user);

    // Clear cache
    await this.cacheManager.del(`user:${userId}`);

    this.logger.log(`User profile updated: ${user.username}`);
    return savedUser;
  }

  async updateLastLogin(userId: number): Promise<void> {
    await this.userRepository.update(userId, {
      lastLoginAt: new Date(),
    });

    // Clear cache
    await this.cacheManager.del(`user:${userId}`);
  }

  async enableTwoFactor(
    userId: number,
  ): Promise<{ secret: string; qrCodeUrl: string }> {
    const user = await this.findById(userId);

    if (user.isTwoFactorEnabled) {
      throw new BadRequestException('2FA is already enabled');
    }

    const { secret, qrCodeUrl } =
      await this.twoFactorService.generateSecret(userId);

    // Update user (don't enable yet, wait for verification)
    await this.userRepository.update(userId, {
      twoFactorSecret: secret,
    });

    // Clear cache
    await this.cacheManager.del(`user:${userId}`);

    return { secret, qrCodeUrl };
  }

  async verifyAndEnableTwoFactor(userId: number, token: string): Promise<void> {
    const user = await this.findById(userId);

    if (!user.twoFactorSecret) {
      throw new BadRequestException('2FA setup not initiated');
    }

    const isValid = await this.twoFactorService.verifyToken(userId, token);
    if (!isValid) {
      throw new BadRequestException('Invalid 2FA token');
    }

    // Enable 2FA
    await this.userRepository.update(userId, {
      isTwoFactorEnabled: true,
    });

    // Clear cache
    await this.cacheManager.del(`user:${userId}`);

    this.logger.log(`2FA enabled for user: ${user.username}`);
  }

  async disableTwoFactor(userId: number): Promise<void> {
    const user = await this.findById(userId);

    await this.userRepository.update(userId, {
      isTwoFactorEnabled: false,
      twoFactorSecret: undefined,
    });

    // Clear cache
    await this.cacheManager.del(`user:${userId}`);

    this.logger.log(`2FA disabled for user: ${user.username}`);
  }

  async uploadAvatar(
    userId: number,
    file: Express.Multer.File,
  ): Promise<string> {
    const user = await this.findById(userId);

    // Delete existing avatar if exists
    if (user.avatar) {
      try {
        const deleted = this.fileUploadService.deleteFile(user.avatar);
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

    // Process avatar image with Sharp for optimization
    const avatarUrl = await this.fileUploadService.processAvatarImage(
      userId,
      file,
    );

    // Update user with new avatar URL
    await this.userRepository.update(userId, { avatar: avatarUrl });

    // Clear cache
    await this.cacheManager.del(`user:${userId}`);

    this.logger.log(`Avatar uploaded for user: ${user.username}`);
    return avatarUrl;
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
    await this.cacheManager.del(`user:${userId}`);

    this.logger.log(`Avatar removed for user: ${user.username}`);
  }

  async deleteUser(userId: number): Promise<void> {
    const user = await this.findById(userId);

    // Soft delete - mark as inactive instead of hard delete
    await this.userRepository.update(userId, { isActive: false });

    // Clear cache
    await this.cacheManager.del(`user:${userId}`);

    this.logger.log(`User deactivated: ${user.username}`);
  }

  async getUserStats(userId: number): Promise<{
    totalClients: number;
    activeTokens: number;
    lastLogin: Date | null;
  }> {
    const user = await this.findById(userId);

    // TODO: Implement proper client and token counting
    // For now, return placeholder values until related services are implemented

    // Count user's OAuth2 clients (when ClientService is implemented)
    const totalClients = 0; // await this.clientService.countByUserId(userId);

    // Count active tokens for user (when TokenService is implemented)
    const activeTokens = 0; // await this.tokenService.countActiveByUserId(userId);

    return {
      totalClients,
      activeTokens,
      lastLogin: user.lastLoginAt || null,
    };
  }
}
