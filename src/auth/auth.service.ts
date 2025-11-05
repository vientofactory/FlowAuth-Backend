import {
  Injectable,
  UnauthorizedException,
  Logger,
  BadRequestException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, MoreThan } from 'typeorm';
import { JwtService } from '@nestjs/jwt';
import { User } from './user.entity';
import { PasswordResetToken } from './password-reset-token.entity';
import { EmailVerificationToken } from './email-verification-token.entity';
import { Client } from '../oauth2/client.entity';
import { Token } from '../oauth2/token.entity';
import { TokenDto } from './dto/response.dto';
import { CreateUserDto } from './dto/create-user.dto';
import { CreateClientDto } from './dto/create-client.dto';
import {
  RequestPasswordResetDto,
  ResetPasswordDto,
} from './dto/password-reset.dto';
import {
  AUTH_CONSTANTS,
  TOKEN_TYPES,
  type TokenType,
} from '../constants/auth.constants';
import { JwtPayload, LoginResponse } from '../types/auth.types';
import { PermissionUtils } from '../utils/permission.util';
import { UserAuthService } from './services/user-auth.service';
import { ClientAuthService } from './services/client-auth.service';
import { TwoFactorAuthService } from './services/two-factor-auth.service';
import { ValidationService } from './services/validation.service';
import type { AvailabilityResult } from '../constants/validation.constants';
import { EmailService } from '../email/email.service';
import { randomBytes } from 'crypto';
import * as bcrypt from 'bcrypt';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
    @InjectRepository(PasswordResetToken)
    private passwordResetTokenRepository: Repository<PasswordResetToken>,
    @InjectRepository(EmailVerificationToken)
    private emailVerificationTokenRepository: Repository<EmailVerificationToken>,
    @InjectRepository(Client)
    private clientRepository: Repository<Client>,
    @InjectRepository(Token)
    private tokenRepository: Repository<Token>,
    private jwtService: JwtService,
    private userAuthService: UserAuthService,
    private clientAuthService: ClientAuthService,
    private twoFactorAuthService: TwoFactorAuthService,
    private validationService: ValidationService,
    private emailService: EmailService,
  ) {}

  async register(createUserDto: CreateUserDto): Promise<User> {
    const user = await this.userAuthService.register(createUserDto);

    // 이메일 인증 토큰 생성 및 비동기 전송 (즉시 응답)
    try {
      const verificationToken = await this.generateEmailVerificationToken(
        user.email,
        user.id,
      );
      this.emailService.sendEmailVerificationAsync(
        user.email,
        user.username,
        verificationToken.token,
      );
      this.logger.log(`Verification email queued for ${user.email}`);
    } catch (error) {
      this.logger.warn(
        `Failed to queue verification email for ${user.email}: ${error instanceof Error ? error.message : 'Unknown error'}`,
      );
    }

    // 회원가입 완료 시 환영 이메일 비동기 전송 (즉시 응답)
    this.emailService.sendWelcomeEmailAsync(user.email, user.username);
    this.logger.log(`Welcome email queued for ${user.email}`);

    return user;
  }

  async checkEmailAvailability(email: string): Promise<AvailabilityResult> {
    return this.validationService.checkEmailAvailability(email);
  }

  async checkUsernameAvailability(
    username: string,
  ): Promise<AvailabilityResult> {
    return this.validationService.checkUsernameAvailability(username);
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
    return this.userAuthService.login(loginDto, clientInfo);
  }

  async verifyTwoFactorToken(
    email: string,
    token: string,
  ): Promise<LoginResponse> {
    return this.twoFactorAuthService.verifyTwoFactorToken(email, token);
  }

  async verifyBackupCode(
    email: string,
    backupCode: string,
  ): Promise<LoginResponse> {
    return this.twoFactorAuthService.verifyBackupCode(email, backupCode);
  }

  async createClient(
    createClientDto: CreateClientDto,
    userId: number,
  ): Promise<Client> {
    return this.clientAuthService.createClient(createClientDto, userId);
  }

  async getClients(userId: number): Promise<Client[]> {
    return this.clientAuthService.getClients(userId);
  }

  async getClientById(id: number, userId: number): Promise<Client> {
    return this.clientAuthService.getClientById(id, userId);
  }

  async updateClientStatus(
    id: number,
    isActive: boolean,
    userId: number,
  ): Promise<Client> {
    const client = await this.clientRepository.findOne({
      where: { id, userId },
    });

    if (!client) {
      throw new UnauthorizedException('Client not found or access denied');
    }

    await this.clientRepository.update(id, { isActive });

    const updatedClient = await this.clientRepository.findOne({
      where: { id, userId },
    });
    if (!updatedClient) {
      throw new UnauthorizedException('Client not found after update');
    }

    return updatedClient;
  }

  async updateClient(
    id: number,
    updateData: Partial<CreateClientDto>,
    userId: number,
  ): Promise<Client> {
    const client = await this.clientRepository.findOne({
      where: { id, userId },
    });

    if (!client) {
      throw new UnauthorizedException('Client not found or access denied');
    }

    // Update only provided fields
    const updateFields: Partial<Client> = {};
    if (updateData.name !== undefined) updateFields.name = updateData.name;
    if (updateData.description !== undefined)
      updateFields.description = updateData.description || undefined;
    if (updateData.redirectUris !== undefined)
      updateFields.redirectUris = updateData.redirectUris;
    if (updateData.scopes !== undefined)
      updateFields.scopes = updateData.scopes;
    if (updateData.logoUri !== undefined)
      updateFields.logoUri = updateData.logoUri || undefined;
    if (updateData.termsOfServiceUri !== undefined)
      updateFields.termsOfServiceUri =
        updateData.termsOfServiceUri || undefined;
    if (updateData.policyUri !== undefined)
      updateFields.policyUri = updateData.policyUri || undefined;

    await this.clientRepository.update(id, updateFields);

    const updatedClient = await this.clientRepository.findOne({
      where: { id },
    });
    if (!updatedClient) {
      throw new UnauthorizedException('Client not found after update');
    }

    return updatedClient;
  }

  async resetClientSecret(id: number, userId: number): Promise<Client> {
    return this.clientAuthService.resetClientSecret(id, userId);
  }

  async removeClientLogo(id: number, userId: number): Promise<Client> {
    return this.clientAuthService.removeClientLogo(id, userId);
  }

  async deleteClient(id: number, userId: number): Promise<void> {
    return this.clientAuthService.deleteClient(id, userId);
  }

  async getUserTokens(userId: number): Promise<TokenDto[]> {
    const tokens = await this.tokenRepository.find({
      where: { user: { id: userId }, isRevoked: false },
      relations: ['client', 'user'],
      order: { createdAt: 'DESC' },
    });

    return tokens.map((token) => ({
      id: token.id,
      tokenType: token.tokenType,
      expiresAt: token.expiresAt.toISOString(),
      refreshExpiresAt: token.refreshExpiresAt?.toISOString(),
      scopes: token.scopes,
      userId: token.user!.id,
      clientId: token.client?.id,
      client: token.client
        ? {
            name: token.client.name,
            clientId: token.client.clientId,
          }
        : undefined,
      createdAt: token.createdAt.toISOString(),
      updatedAt: token.createdAt.toISOString(), // Use createdAt since updatedAt doesn't exist
    }));
  }

  async revokeToken(userId: number, tokenId: number): Promise<void> {
    const token = await this.tokenRepository.findOne({
      where: { id: tokenId, user: { id: userId } },
    });

    if (!token) {
      throw new UnauthorizedException('Token not found');
    }

    // Completely delete token to ensure session expiration
    await this.tokenRepository.delete({ id: tokenId });
  }

  async revokeAllUserTokens(userId: number): Promise<void> {
    await this.tokenRepository.delete({ user: { id: userId } });
  }

  async revokeAllTokensForType(
    userId: number,
    tokenType: TokenType,
  ): Promise<void> {
    await this.tokenRepository.delete({ user: { id: userId }, tokenType });
  }

  // JWT token refresh (for general login)
  async refreshToken(token: string): Promise<LoginResponse> {
    try {
      // Validate token
      const payload = this.jwtService.verify<JwtPayload>(token);

      // Find user
      const user = await this.userRepository.findOne({
        where: { id: parseInt(payload.sub, 10) },
        select: [
          'id',
          'email',
          'username',
          'firstName',
          'lastName',
          'permissions',
          'userType',
        ],
      });

      if (!user) {
        throw new UnauthorizedException('User not found');
      }

      // Generate new token (same method as before)
      const newPayload: JwtPayload = {
        sub: user.id.toString(),
        email: user.email,
        username: user.username,
        roles: [PermissionUtils.getRoleName(user.permissions)],
        permissions: user.permissions,
        type: TOKEN_TYPES.LOGIN,
      };

      const accessToken = this.jwtService.sign(newPayload);

      return {
        user,
        accessToken,
        expiresIn: AUTH_CONSTANTS.TOKEN_EXPIRATION_SECONDS,
      };
    } catch (error) {
      this.logger.error('Token refresh error:', error);
      throw new UnauthorizedException('Invalid or expired token');
    }
  }

  // Logout
  logout(token: string): { message: string } {
    try {
      // Validate token (optional: add to blacklist or perform other cleanup)
      this.jwtService.verify(token);

      return { message: 'Logged out successfully' };
    } catch (error) {
      this.logger.error('Logout error:', error);
      throw new UnauthorizedException('Invalid token');
    }
  }

  /**
   * 비밀번호 재설정 요청
   */
  async requestPasswordReset(
    requestPasswordResetDto: RequestPasswordResetDto,
  ): Promise<{ message: string }> {
    const { email } = requestPasswordResetDto;

    // 사용자 존재 여부 확인
    const user = await this.userRepository.findOne({ where: { email } });
    if (!user) {
      // 보안을 위해 사용자가 존재하지 않아도 성공 메시지 반환
      this.logger.warn(
        `Password reset requested for non-existent email: ${email}`,
      );
      return { message: '비밀번호 재설정 링크가 이메일로 전송되었습니다.' };
    }

    try {
      // 기존 토큰들을 만료시킴
      await this.passwordResetTokenRepository.update(
        { userId: user.id, used: false },
        { used: true },
      );

      // 새 토큰 생성 (1시간 유효)
      const token = randomBytes(32).toString('hex');
      const expiresAt = new Date();
      expiresAt.setHours(expiresAt.getHours() + 1);

      // 토큰을 데이터베이스에 저장
      const resetToken = this.passwordResetTokenRepository.create({
        token,
        userId: user.id,
        email: user.email,
        expiresAt,
      });
      await this.passwordResetTokenRepository.save(resetToken);

      // 비밀번호 재설정 이메일 비동기 전송 (즉시 응답)
      this.emailService.sendPasswordResetAsync(
        user.email,
        user.username,
        token,
      );

      this.logger.log(`Password reset email queued for ${user.email}`);
      return { message: '비밀번호 재설정 링크가 이메일로 전송되었습니다.' };
    } catch (error) {
      this.logger.error(
        `Failed to process password reset request for ${email}: ${error instanceof Error ? error.message : 'Unknown error'}`,
      );
      throw new BadRequestException(
        '비밀번호 재설정 요청 처리 중 오류가 발생했습니다.',
      );
    }
  }

  /**
   * 비밀번호 재설정 실행
   */
  async resetPassword(
    resetPasswordDto: ResetPasswordDto,
  ): Promise<{ message: string }> {
    const { token, newPassword } = resetPasswordDto;

    // 토큰 조회 및 유효성 검증
    const resetToken = await this.passwordResetTokenRepository.findOne({
      where: {
        token,
        used: false,
        expiresAt: MoreThan(new Date()),
      },
      relations: ['user'],
    });

    if (!resetToken) {
      throw new BadRequestException('유효하지 않거나 만료된 토큰입니다.');
    }

    try {
      // 비밀번호 해시화
      const saltRounds = 12;
      const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

      // 사용자 비밀번호 업데이트
      await this.userRepository.update(
        { id: resetToken.userId },
        { password: hashedPassword },
      );

      // 토큰을 사용됨으로 표시
      await this.passwordResetTokenRepository.update(
        { id: resetToken.id },
        { used: true },
      );

      // 보안 알림 이메일 전송
      try {
        await this.emailService.sendSecurityAlert(
          resetToken.user.email,
          resetToken.user.username,
          '비밀번호 변경',
          {
            action: '비밀번호가 성공적으로 변경되었습니다.',
            timestamp: new Date().toLocaleString('ko-KR'),
          },
        );
      } catch (emailError) {
        this.logger.warn(
          `Failed to send security alert email: ${emailError instanceof Error ? emailError.message : 'Unknown error'}`,
        );
      }

      this.logger.log(
        `Password reset completed for user: ${resetToken.user.email}`,
      );
      return { message: '비밀번호가 성공적으로 변경되었습니다.' };
    } catch (error) {
      this.logger.error(
        `Failed to reset password: ${error instanceof Error ? error.message : 'Unknown error'}`,
      );
      throw new BadRequestException('비밀번호 재설정 중 오류가 발생했습니다.');
    }
  }

  /**
   * 비밀번호 재설정 토큰 유효성 확인
   */
  async validatePasswordResetToken(
    token: string,
  ): Promise<{ valid: boolean; email?: string }> {
    const resetToken = await this.passwordResetTokenRepository.findOne({
      where: {
        token,
        used: false,
        expiresAt: MoreThan(new Date()),
      },
    });

    if (!resetToken) {
      return { valid: false };
    }

    return { valid: true, email: resetToken.email };
  }

  /**
   * 이메일 인증 토큰 생성
   */
  private async generateEmailVerificationToken(
    email: string,
    userId: number,
  ): Promise<EmailVerificationToken> {
    // 기존 미사용 토큰 삭제
    await this.emailVerificationTokenRepository.delete({
      email,
      used: false,
    });

    const token = randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24시간

    const verificationToken = this.emailVerificationTokenRepository.create({
      token,
      email,
      userId,
      expiresAt,
    });

    return this.emailVerificationTokenRepository.save(verificationToken);
  }

  /**
   * 이메일 인증 재전송
   */
  async resendEmailVerification(email: string): Promise<{ message: string }> {
    const user = await this.userRepository.findOne({
      where: { email: email.trim().toLowerCase() },
    });

    if (!user) {
      throw new BadRequestException('존재하지 않는 이메일입니다.');
    }

    if (user.isEmailVerified) {
      throw new BadRequestException('이미 인증된 이메일입니다.');
    }

    try {
      const verificationToken = await this.generateEmailVerificationToken(
        user.email,
        user.id,
      );

      await this.emailService.sendEmailVerification(
        user.email,
        user.username,
        verificationToken.token,
      );

      this.logger.log(`Verification email resent to ${user.email}`);
      return { message: '인증 이메일이 전송되었습니다.' };
    } catch (error) {
      this.logger.error(
        `Failed to resend verification email: ${error instanceof Error ? error.message : 'Unknown error'}`,
      );
      throw new BadRequestException('이메일 전송 중 오류가 발생했습니다.');
    }
  }

  /**
   * 이메일 인증 확인
   */
  async verifyEmail(token: string): Promise<{ message: string }> {
    const verificationToken =
      await this.emailVerificationTokenRepository.findOne({
        where: {
          token,
          used: false,
          expiresAt: MoreThan(new Date()),
        },
        relations: ['user'],
      });

    if (!verificationToken) {
      throw new BadRequestException('유효하지 않거나 만료된 인증 토큰입니다.');
    }

    try {
      // 사용자 이메일 인증 완료 처리
      await this.userRepository.update(
        { id: verificationToken.userId },
        { isEmailVerified: true },
      );

      // 토큰을 사용됨으로 표시
      await this.emailVerificationTokenRepository.update(
        { id: verificationToken.id },
        { used: true },
      );

      this.logger.log(
        `Email verification completed for user: ${verificationToken.user.email}`,
      );
      return { message: '이메일이 성공적으로 인증되었습니다.' };
    } catch (error) {
      this.logger.error(
        `Failed to verify email: ${error instanceof Error ? error.message : 'Unknown error'}`,
      );
      throw new BadRequestException('이메일 인증 중 오류가 발생했습니다.');
    }
  }

  /**
   * 이메일 인증 토큰 유효성 확인
   */
  async validateEmailVerificationToken(
    token: string,
  ): Promise<{ valid: boolean; email?: string }> {
    const verificationToken =
      await this.emailVerificationTokenRepository.findOne({
        where: {
          token,
          used: false,
          expiresAt: MoreThan(new Date()),
        },
      });

    if (!verificationToken) {
      return { valid: false };
    }

    return { valid: true, email: verificationToken.email };
  }
}
