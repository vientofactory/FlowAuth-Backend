import { Injectable, UnauthorizedException, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { JwtService } from '@nestjs/jwt';
import * as crypto from 'crypto';
import { User } from '../user.entity';
import { Token } from '../../oauth2/token.entity';
import {
  AUTH_CONSTANTS,
  AUTH_ERROR_MESSAGES,
  TOKEN_TYPES,
} from '../../constants/auth.constants';
import { JwtPayload, LoginResponse } from '../../types/auth.types';
import { PermissionUtils } from '../../utils/permission.util';
import { TwoFactorService } from '../two-factor.service';

@Injectable()
export class TwoFactorAuthService {
  private readonly logger = new Logger(TwoFactorAuthService.name);

  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
    @InjectRepository(Token)
    private tokenRepository: Repository<Token>,
    private jwtService: JwtService,
    private twoFactorService: TwoFactorService,
  ) {}

  async verifyTwoFactorToken(
    email: string,
    token: string,
  ): Promise<LoginResponse> {
    this.logger.log(`2FA token verification attempt for email: ${email}`);
    try {
      // Find user with 2FA fields and email verification status
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
          'isEmailVerified',
          'avatar',
        ],
      });

      if (!user) {
        throw new UnauthorizedException(
          AUTH_ERROR_MESSAGES.INVALID_CREDENTIALS,
        );
      }

      // Check if email is verified
      if (!user.isEmailVerified) {
        throw new UnauthorizedException(
          '이메일 인증이 완료되지 않았습니다. 이메일을 확인하여 계정을 인증해주세요.',
        );
      }

      if (!user.isTwoFactorEnabled || !user.twoFactorSecret) {
        throw new UnauthorizedException(
          AUTH_ERROR_MESSAGES.TWO_FACTOR_NOT_ENABLED,
        );
      }

      // Verify TOTP token
      const isValid = await this.twoFactorService.verifyToken(user.id, token);

      if (!isValid) {
        throw new UnauthorizedException(
          AUTH_ERROR_MESSAGES.INVALID_TWO_FACTOR_TOKEN,
        );
      }

      // Generate JWT tokens
      const payload: JwtPayload = {
        sub: user.id.toString(),
        email: user.email,
        username: user.username,
        roles: [PermissionUtils.getRoleName(user.permissions)],
        permissions: user.permissions,
        type: TOKEN_TYPES.LOGIN,
      };

      const accessToken = this.jwtService.sign(payload);
      const refreshToken = crypto.randomBytes(32).toString('hex');

      const refreshExpiresAt = new Date();
      refreshExpiresAt.setDate(refreshExpiresAt.getDate() + 30); // 30 days

      // Store refresh token in database
      const tokenEntity = this.tokenRepository.create({
        accessToken,
        refreshToken,
        expiresAt: new Date(
          Date.now() + AUTH_CONSTANTS.TOKEN_EXPIRATION_SECONDS * 1000,
        ),
        refreshExpiresAt,
        scopes: undefined, // 로그인 토큰은 스코프 대신 JWT payload의 permissions 사용
        user,
        tokenType: TOKEN_TYPES.LOGIN,
        isRefreshTokenUsed: false,
      });
      await this.tokenRepository.save(tokenEntity);

      return {
        user,
        accessToken,
        refreshToken,
        expiresIn: AUTH_CONSTANTS.TOKEN_EXPIRATION_SECONDS,
      };
    } catch (error) {
      if (error instanceof UnauthorizedException) {
        throw error;
      }

      // 프로덕션에서는 실제 에러를 로그에 기록하되 사용자에게는 일반적인 메시지 반환
      this.logger.error(
        'Two-factor token verification failed with unexpected error:',
        {
          error: error instanceof Error ? error.message : String(error),
          stack: error instanceof Error ? error.stack : undefined,
          email,
          timestamp: new Date().toISOString(),
        },
      );

      throw new UnauthorizedException(AUTH_ERROR_MESSAGES.LOGIN_FAILED);
    }
  }

  async verifyBackupCode(
    email: string,
    backupCode: string,
  ): Promise<LoginResponse> {
    try {
      // Find user with email verification status
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
          'isEmailVerified',
          'avatar',
        ],
      });

      if (!user) {
        throw new UnauthorizedException(
          AUTH_ERROR_MESSAGES.INVALID_CREDENTIALS,
        );
      }

      // Check if email is verified
      if (!user.isEmailVerified) {
        throw new UnauthorizedException(
          '이메일 인증이 완료되지 않았습니다. 이메일을 확인하여 계정을 인증해주세요.',
        );
      }

      if (!user.isTwoFactorEnabled) {
        throw new UnauthorizedException(
          AUTH_ERROR_MESSAGES.TWO_FACTOR_NOT_ENABLED,
        );
      }

      // Verify backup code
      const isValidBackupCode = await this.twoFactorService.verifyBackupCode(
        user.id,
        backupCode,
      );

      if (!isValidBackupCode) {
        throw new UnauthorizedException(
          AUTH_ERROR_MESSAGES.INVALID_BACKUP_CODE,
        );
      }

      // Generate JWT tokens
      const payload: JwtPayload = {
        sub: user.id.toString(),
        email: user.email,
        username: user.username,
        roles: [PermissionUtils.getRoleName(user.permissions)],
        permissions: user.permissions,
        type: TOKEN_TYPES.LOGIN,
      };

      const accessToken = this.jwtService.sign(payload);
      const refreshToken = crypto.randomBytes(32).toString('hex');

      const refreshExpiresAt = new Date();
      refreshExpiresAt.setDate(refreshExpiresAt.getDate() + 30); // 30 days

      // Store refresh token in database
      const tokenEntity = this.tokenRepository.create({
        accessToken,
        refreshToken,
        expiresAt: new Date(
          Date.now() + AUTH_CONSTANTS.TOKEN_EXPIRATION_SECONDS * 1000,
        ),
        refreshExpiresAt,
        scopes: undefined, // 로그인 토큰은 스코프 대신 JWT payload의 permissions 사용
        user,
        tokenType: TOKEN_TYPES.LOGIN,
        isRefreshTokenUsed: false,
      });
      await this.tokenRepository.save(tokenEntity);

      return {
        user,
        accessToken,
        refreshToken,
        expiresIn: AUTH_CONSTANTS.TOKEN_EXPIRATION_SECONDS,
      };
    } catch (error) {
      if (error instanceof UnauthorizedException) {
        throw error;
      }

      this.logger.error('Backup code verification failed:', error);
      throw new UnauthorizedException(AUTH_ERROR_MESSAGES.LOGIN_FAILED);
    }
  }
}
