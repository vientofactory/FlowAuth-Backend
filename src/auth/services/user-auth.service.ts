import {
  Injectable,
  ConflictException,
  UnauthorizedException,
  Logger,
  Inject,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import type { Cache } from 'cache-manager';
import { JwtService } from '@nestjs/jwt';
import { User } from '../user.entity';
import { Token } from '../../oauth2/token.entity';
import { CreateUserDto } from '../dto/create-user.dto';
import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';
import {
  AUTH_CONSTANTS,
  AUTH_ERROR_MESSAGES,
  PERMISSIONS,
  USER_TYPES,
  USER_TYPE_PERMISSIONS,
  TOKEN_TYPES,
  JWT_TOKEN_EXPIRY,
} from '../../constants/auth.constants';
import { JwtPayload, LoginResponse } from '../../types/auth.types';
import { PermissionUtils } from '../../utils/permission.util';
import { RecaptchaService } from '../../utils/recaptcha.util';
import { AuditLogService } from '../../common/audit-log.service';
import {
  AuditEventType,
  AuditSeverity,
  AuditLog,
} from '../../common/audit-log.entity';

@Injectable()
export class UserAuthService {
  private readonly logger = new Logger(UserAuthService.name);

  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
    @InjectRepository(Token)
    private tokenRepository: Repository<Token>,
    private jwtService: JwtService,
    private configService: ConfigService,
    private recaptchaService: RecaptchaService,
    @Inject(CACHE_MANAGER)
    private cacheManager: Cache,
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

    // Check if user already exists
    const existingUser = await this.userRepository.findOne({
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

    // Check if this is the first user (should get admin permissions)
    const userCount = await this.userRepository.count();
    const isFirstUser = userCount === 0;

    // Determine user type and permissions
    const finalUserType = userType ?? USER_TYPES.REGULAR;
    let permissions: number;

    if (isFirstUser) {
      // First user is always admin
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

    // Create user
    const user = this.userRepository.create({
      username,
      email,
      password: hashedPassword,
      firstName,
      lastName,
      userType: finalUserType,
      permissions,
    });

    return this.userRepository.save(user);
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

    try {
      // Find user with 2FA fields
      const user = await this.userRepository.findOne({
        where: { email },
        select: [
          'id',
          'email',
          'username',
          'password',
          'firstName',
          'lastName',
          'permissions',
          'userType',
          'isTwoFactorEnabled',
          'twoFactorSecret',
          'avatar',
        ],
      });

      if (!user) {
        throw new UnauthorizedException(
          AUTH_ERROR_MESSAGES.INVALID_CREDENTIALS,
        );
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
        throw new UnauthorizedException(
          AUTH_ERROR_MESSAGES.INVALID_CREDENTIALS,
        );
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
      await this.cacheManager.del(`stats:${user.id}`);
      await this.cacheManager.del(`activities:${user.id}:10`); // default limit 10

      // Generate JWT token with enhanced payload
      const payload: JwtPayload = {
        sub: user.id.toString(),
        email: user.email,
        username: user.username,
        roles: [PermissionUtils.getRoleName(user.permissions)],
        permissions: user.permissions,
        type: TOKEN_TYPES.LOGIN,
        avatar: user.avatar ?? undefined,
      };
      // Generate JWT token (24 hours for login tokens)
      const accessToken = this.jwtService.sign(payload, {
        expiresIn: `${JWT_TOKEN_EXPIRY.LOGIN_HOURS}h`,
      });

      // Generate refresh token for general login
      const refreshToken = crypto.randomBytes(32).toString('hex');
      const refreshExpiresAt = new Date();
      refreshExpiresAt.setDate(refreshExpiresAt.getDate() + 30); // 30 days

      // Store refresh token in database first
      const tokenEntity = this.tokenRepository.create({
        accessToken,
        refreshToken,
        expiresAt: new Date(
          Date.now() + AUTH_CONSTANTS.TOKEN_EXPIRATION_SECONDS * 1000,
        ),
        refreshExpiresAt,
        scopes: undefined, // Login tokens use JWT payload permissions instead of scopes
        user,
        tokenType: TOKEN_TYPES.LOGIN,
        isRefreshTokenUsed: false,
      });
      await this.tokenRepository.save(tokenEntity);

      // Regenerate JWT with tokenId for immediate revocation capability
      const finalPayload: JwtPayload = {
        ...payload,
        jti: tokenEntity.id.toString(), // Include token ID for revocation
      };
      const finalAccessToken = this.jwtService.sign(finalPayload, {
        expiresIn: `${JWT_TOKEN_EXPIRY.LOGIN_HOURS}h`,
      });

      // Update token with final access token
      tokenEntity.accessToken = finalAccessToken;
      await this.tokenRepository.save(tokenEntity);

      return {
        user,
        accessToken: finalAccessToken,
        refreshToken,
        expiresIn: AUTH_CONSTANTS.TOKEN_EXPIRATION_SECONDS,
      };
    } catch (error) {
      this.logger.error(`Login failed for email: ${email}`, error.stack);
      throw error;
    }
  }
}
