import {
  Injectable,
  ConflictException,
  UnauthorizedException,
  Logger,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectRepository, InjectDataSource } from '@nestjs/typeorm';
import { Repository, DataSource } from 'typeorm';
import { JwtService } from '@nestjs/jwt';
import { User } from '../user.entity';
import { Token } from '../../oauth2/token.entity';
import { CreateUserDto } from '../dto/create-user.dto';
import * as bcrypt from 'bcrypt';
import { randomBytes } from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import {
  AUTH_CONSTANTS,
  AUTH_ERROR_MESSAGES,
  PERMISSIONS,
  USER_TYPES,
  USER_TYPE_PERMISSIONS,
  TOKEN_TYPES,
  JWT_TOKEN_EXPIRY,
  PERMISSION_UTILS,
  TOKEN_EXPIRY_DAYS,
} from '@flowauth/shared';
import { JwtPayload, LoginResponse } from '../../types/auth.types';
import { PermissionUtils } from '../../utils/permission.util';
import { RecaptchaService } from '../../utils/recaptcha.util';
import { AuditLogService } from '../../common/audit-log.service';
import { snowflakeGenerator } from '../../utils/snowflake-id.util';
import {
  AuditEventType,
  AuditSeverity,
  AuditLog,
} from '../../common/audit-log.entity';
import { CacheManagerService } from '../../cache/cache-manager.service';

@Injectable()
export class UserAuthService {
  private readonly logger = new Logger(UserAuthService.name);

  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
    @InjectRepository(Token)
    private tokenRepository: Repository<Token>,
    @InjectDataSource()
    private dataSource: DataSource,
    private jwtService: JwtService,
    private configService: ConfigService,
    private recaptchaService: RecaptchaService,
    private cacheManagerService: CacheManagerService,
    private auditLogService: AuditLogService,
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

    // Use transaction to prevent race conditions during user registration
    return this.dataSource.transaction(async (manager) => {
      // Check if user already exists within transaction
      const existingUser = await manager.findOne(User, {
        where: [{ username }, { email }],
      });

      if (existingUser) {
        throw new ConflictException(AUTH_ERROR_MESSAGES.USER_ALREADY_EXISTS);
      }

      // Hash password
      const hashedPassword = await bcrypt.hash(
        password,
        AUTH_CONSTANTS.BCRYPT_SALT_ROUNDS,
      );

      // Check if this is the first user (should get admin permissions) within transaction
      const userCount = await manager.count(User);
      const isFirstUser = userCount === 0;

      // Determine user type and permissions
      const finalUserType = userType ?? USER_TYPES.REGULAR;
      let permissions: number;

      if (isFirstUser) {
        // First user of entire system gets admin access
        permissions = PERMISSIONS.ADMIN_ACCESS;
      } else {
        // Set permissions based on user type
        if (
          Object.prototype.hasOwnProperty.call(
            USER_TYPE_PERMISSIONS,
            finalUserType,
          )
        ) {
          permissions =
            USER_TYPE_PERMISSIONS[
              finalUserType as keyof typeof USER_TYPE_PERMISSIONS
            ];
        } else {
          throw new Error(`Invalid user type: ${finalUserType}`);
        }
      }

      // Validate permissions
      if (
        permissions <= 0 ||
        (permissions !== PERMISSIONS.ADMIN_ACCESS &&
          (permissions & ~PERMISSION_UTILS.getAllPermissionsMask()) !== 0)
      ) {
        throw new Error(`Invalid permissions value: ${permissions}`);
      }

      // Generate userId using Snowflake ID
      const userId = await snowflakeGenerator.generate();

      // Create user within transaction
      const user = manager.create(User, {
        username,
        email,
        password: hashedPassword,
        firstName,
        lastName,
        userType: finalUserType,
        permissions,
        userId,
      });

      return manager.save(user);
    });
  }

  async login(
    loginDto: {
      email: string;
      password: string;
      recaptchaToken: string;
    },
    clientInfo?: {
      userAgent: string;
      ipAddress: string;
    },
  ): Promise<LoginResponse> {
    const { email, password, recaptchaToken } = loginDto;

    // Verify reCAPTCHA token (required for login)
    const isValidRecaptcha = await this.recaptchaService.verifyToken(
      recaptchaToken,
      'login',
    );
    if (!isValidRecaptcha) {
      // Log failed authentication due to reCAPTCHA
      try {
        await this.auditLogService.create(
          AuditLog.createFailedAuthEvent(
            email,
            clientInfo?.ipAddress ?? 'unknown',
            clientInfo?.userAgent ?? 'unknown',
            'reCAPTCHA verification failed',
          ),
        );
      } catch (auditError) {
        this.logger.warn(
          'Failed to create audit log for failed auth:',
          auditError,
        );
      }
      throw new UnauthorizedException('reCAPTCHA verification failed');
    }

    // Find user with 2FA fields and email verification status
    const user = await this.userRepository.findOne({
      where: { email },
      select: [
        'id',
        'userId',
        'email',
        'username',
        'password',
        'firstName',
        'lastName',
        'permissions',
        'userType',
        'isTwoFactorEnabled',
        'twoFactorSecret',
        'isEmailVerified',
        'avatar',
      ],
    });

    if (!user) {
      throw new UnauthorizedException(AUTH_ERROR_MESSAGES.INVALID_CREDENTIALS);
    }

    // Generate userId if not exists (for existing users) - use transaction for atomicity
    if (!user.userId) {
      await this.dataSource.transaction(async (manager) => {
        // Re-fetch user within transaction to prevent race conditions
        const userInTransaction = await manager.findOne(User, {
          where: { id: user.id },
          lock: { mode: 'pessimistic_write' },
        });

        if (userInTransaction && !userInTransaction.userId) {
          userInTransaction.userId = await snowflakeGenerator.generate();
          await manager.save(userInTransaction);
          user.userId = userInTransaction.userId;
          this.logger.log(
            `Generated Snowflake ID for existing user: ${user.username} (${user.userId})`,
          );
        } else if (userInTransaction?.userId) {
          // Another concurrent request already generated the userId
          user.userId = userInTransaction.userId;
        }
      });
    }

    // Check password
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      // Log failed authentication due to invalid password
      try {
        await this.auditLogService.create(
          AuditLog.createFailedAuthEvent(
            email,
            clientInfo?.ipAddress ?? 'unknown',
            clientInfo?.userAgent ?? 'unknown',
            'Invalid password',
          ),
        );
      } catch (auditError) {
        this.logger.warn(
          'Failed to create audit log for failed auth:',
          auditError,
        );
      }
      throw new UnauthorizedException(AUTH_ERROR_MESSAGES.INVALID_CREDENTIALS);
    }

    // Check if 2FA is enabled
    if (user.isTwoFactorEnabled) {
      // Return special response indicating 2FA is required
      throw new UnauthorizedException('2FA_REQUIRED');
    }

    // Update last login time
    await this.userRepository.update(user.id, {
      lastLoginAt: new Date(),
    });

    // Log audit event for successful login
    try {
      await this.auditLogService.create({
        eventType: AuditEventType.USER_LOGIN,
        severity: AuditSeverity.LOW,
        description: `사용자 ${user.username}(${user.email}) 로그인`,
        userId: user.id,
        userAgent: clientInfo?.userAgent ?? 'unknown',
        ipAddress: clientInfo?.ipAddress ?? 'unknown',
        metadata: {
          loginMethod: 'password',
          userAgent: clientInfo?.userAgent ?? 'unknown',
          ipAddress: clientInfo?.ipAddress ?? 'unknown',
        },
      });
    } catch (auditError) {
      // Audit log creation failure should not affect login success
      this.logger.warn('Failed to create audit log for login:', auditError);
    }

    // Invalidate dashboard cache on successful login (statistics update due to lastLoginAt change)
    await this.cacheManagerService.delCacheKey(`stats:${user.id}`);
    await this.cacheManagerService.delCacheKey(`activities:${user.id}:10`); // default limit 10

    // Generate refresh token for general login
    const refreshToken = randomBytes(32).toString('hex');
    const refreshExpiresAt = new Date();
    refreshExpiresAt.setDate(
      refreshExpiresAt.getDate() + TOKEN_EXPIRY_DAYS.REFRESH_TOKEN,
    );

    // Use transaction to ensure atomic token creation
    const result = await this.dataSource.transaction(async (manager) => {
      try {
        // Create token entity without access token first
        const tokenEntity = manager.create(Token, {
          accessToken: '', // Will be updated with actual JWT
          refreshToken,
          expiresAt: new Date(
            Date.now() + AUTH_CONSTANTS.TOKEN_EXPIRATION_SECONDS * 1000,
          ),
          refreshExpiresAt,
          scopes: undefined,
          user,
          tokenType: TOKEN_TYPES.LOGIN,
          tokenFamily: uuidv4(),
          rotationGeneration: 1,
          isRefreshTokenUsed: false,
        });

        // Save to get the token ID
        const savedToken = await manager.save(tokenEntity);

        // Generate JWT payload with token ID
        const payload: JwtPayload = {
          sub: user.id.toString(),
          email: user.email,
          username: user.username,
          roles: [PermissionUtils.getRoleName(user.permissions)],
          permissions: user.permissions,
          type: TOKEN_TYPES.LOGIN,
          avatar: user.avatar ?? undefined,
          jti: savedToken.id.toString(), // Include token ID for revocation
        };

        // Generate final JWT token with jti
        const finalAccessToken = this.jwtService.sign(payload, {
          expiresIn: `${JWT_TOKEN_EXPIRY.LOGIN_HOURS}h`,
        });

        // Update token with final access token in the same transaction
        savedToken.accessToken = finalAccessToken;
        await manager.save(savedToken);

        return {
          user,
          accessToken: finalAccessToken,
          refreshToken,
          expiresIn: AUTH_CONSTANTS.TOKEN_EXPIRATION_SECONDS,
        };
      } catch (error) {
        this.logger.error('Failed to create token in transaction:', error);
        throw error;
      }
    });

    return result;
  }
}
