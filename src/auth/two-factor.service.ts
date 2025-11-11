import {
  Injectable,
  BadRequestException,
  UnauthorizedException,
  Logger,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import * as speakeasy from 'speakeasy';
import * as QRCode from 'qrcode';
import { User } from './user.entity';
import { TwoFactorResponseDto } from './dto/2fa/two-factor.dto';
import {
  AUTH_ERROR_MESSAGES,
  TWO_FACTOR_CONSTANTS,
} from '../constants/auth.constants';
import * as bcrypt from 'bcrypt';
import { randomBytes } from 'crypto';
import { EmailService } from '../email/email.service';

@Injectable()
export class TwoFactorService {
  private readonly logger = new Logger(TwoFactorService.name);

  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
    private emailService: EmailService,
  ) {}

  /**
   * 2FA 설정을 위한 시크릿 생성
   */
  async generateSecret(userId: number): Promise<TwoFactorResponseDto> {
    const user = await this.userRepository.findOne({ where: { id: userId } });

    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    if (user.isTwoFactorEnabled) {
      throw new BadRequestException('2FA가 이미 활성화되어 있습니다.');
    }

    // 새로운 시크릿 생성
    const secret = speakeasy.generateSecret({
      name: `FlowAuth:${user.username}`,
      issuer: 'FlowAuth',
      length: TWO_FACTOR_CONSTANTS.SECRET_LENGTH,
    });

    // 백업 코드 생성 (10개)
    const backupCodes = this.generateBackupCodes();

    // QR 코드 URL 생성
    const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);

    return {
      secret: secret.base32,
      qrCodeUrl,
      backupCodes,
    };
  }

  /**
   * 2FA 설정 확인 및 활성화
   */
  async enableTwoFactor(
    userId: number,
    token: string,
    secret: string,
    backupCodes: string[],
  ): Promise<void> {
    const user = await this.userRepository.findOne({ where: { id: userId } });

    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    if (user.isTwoFactorEnabled) {
      throw new BadRequestException('2FA가 이미 활성화되어 있습니다.');
    }

    // 토큰 검증
    const isValid = speakeasy.totp.verify({
      secret: secret,
      encoding: 'base32',
      token: token,
      window: 2, // 2단계 윈도우 (시간 오차 허용)
    });

    if (!isValid) {
      throw new BadRequestException('잘못된 2FA 토큰입니다.');
    }

    // 해시된 백업 코드 저장 (하이픈 제거 후 해시)
    const hashedBackupCodes = await Promise.all(
      backupCodes.map((code) => {
        const normalizedCode = code.replace(/-/g, '').toUpperCase();
        return bcrypt.hash(normalizedCode, 10);
      }),
    );

    // 사용자 정보 업데이트
    await this.userRepository.update(userId, {
      twoFactorSecret: secret,
      isTwoFactorEnabled: true,
      backupCodes: hashedBackupCodes,
    });

    // 2FA 활성화 알림 이메일 전송 (큐 기반 비동기)
    try {
      await this.emailService.queue2FAEnabled(user.email, user.username);
      this.logger.log(`2FA enabled notification queued for ${user.email}`);
    } catch (emailError) {
      this.logger.warn(
        `Failed to queue 2FA enabled notification for ${user.email}: ${emailError instanceof Error ? emailError.message : 'Unknown error'}`,
      );
    }
  }

  /**
   * 2FA 토큰 검증
   */
  async verifyToken(userId: number, token: string): Promise<boolean> {
    const user = await this.userRepository.findOne({ where: { id: userId } });

    if (!user?.twoFactorSecret) {
      return false;
    }

    if (!user.isTwoFactorEnabled) {
      throw new UnauthorizedException(
        AUTH_ERROR_MESSAGES.TWO_FACTOR_NOT_ENABLED,
      );
    }

    return speakeasy.totp.verify({
      secret: user.twoFactorSecret,
      encoding: 'base32',
      token: token,
      window: 2,
    });
  }

  /**
   * 백업 코드 검증 (타이밍 공격 방지 포함)
   */
  async verifyBackupCode(userId: number, code: string): Promise<boolean> {
    const user = await this.userRepository.findOne({ where: { id: userId } });

    if (!user) {
      return false;
    }

    // 2FA가 활성화되어 있어야 백업 코드를 사용할 수 있음
    if (!user.isTwoFactorEnabled) {
      throw new UnauthorizedException(
        AUTH_ERROR_MESSAGES.TWO_FACTOR_NOT_ENABLED,
      );
    }

    // 백업 코드가 없으면 사용할 수 없음
    if (!user.backupCodes || user.backupCodes.length === 0) {
      throw new BadRequestException('사용 가능한 백업 코드가 없습니다.');
    }

    // 입력 검증 및 정규화
    const normalizedInputCode = this.normalizeBackupCode(code);
    if (!normalizedInputCode) {
      this.logger.warn(`Invalid backup code format for user ${userId}`);
      return false;
    }

    // 타이밍 공격 방지를 위한 상수 시간 검증
    return this.verifyBackupCodeConstantTime(
      user.backupCodes,
      normalizedInputCode,
      userId,
    );
  }

  /**
   * 백업 코드 정규화 및 검증
   */
  private normalizeBackupCode(code: string): string | null {
    if (!code || typeof code !== 'string') {
      return null;
    }

    // 공백 제거 및 대문자 변환
    const cleaned = code.trim().toUpperCase();

    // 하이픈 제거
    const normalized = cleaned.replace(/-/g, '');

    // 길이 검증 (Base32 12자리 예상)
    if (normalized.length < 8 || normalized.length > 16) {
      return null;
    }

    // Base32 문자 검증 (문자 제외: 0, 1, 8, 9, I, O)
    if (!/^[A-HJ-KM-NP-TV-Z2-7]+$/.test(normalized)) {
      return null;
    }

    return normalized;
  }

  /**
   * 상수 시간 백업 코드 검증 (타이밍 공격 방지)
   */
  private async verifyBackupCodeConstantTime(
    backupCodes: string[],
    inputCode: string,
    userId: number,
  ): Promise<boolean> {
    let foundValidCode = false;
    let validCodeIndex = -1;

    // 모든 백업 코드를 검사하여 타이밍 공격 방지
    const verificationPromises = backupCodes.map(async (hashedCode, index) => {
      if (!hashedCode) return { valid: false, index };

      try {
        const isValid = await bcrypt.compare(inputCode, hashedCode);
        return { valid: isValid, index };
      } catch (error) {
        this.logger.warn(
          `Backup code verification error for user ${userId} at index ${index}: ${error instanceof Error ? error.message : 'Unknown error'}`,
        );
        return { valid: false, index };
      }
    });

    // 모든 검증을 병렬로 실행하여 일정한 시간 소요
    const results = await Promise.all(verificationPromises);

    // 유효한 코드 찾기
    for (const result of results) {
      if (result.valid && !foundValidCode) {
        foundValidCode = true;
        validCodeIndex = result.index;
        // 첫 번째 유효한 코드만 사용하고 계속 검사
      }
    }

    // 유효한 코드가 발견된 경우에만 제거
    if (foundValidCode && validCodeIndex >= 0) {
      try {
        const updatedBackupCodes = [...backupCodes];
        updatedBackupCodes.splice(validCodeIndex, 1);

        await this.userRepository.update(userId, {
          backupCodes: updatedBackupCodes,
        });

        this.logger.log(
          `Backup code used successfully for user ${userId}. Remaining codes: ${updatedBackupCodes.length}`,
        );

        return true;
      } catch (error) {
        this.logger.error(
          `Failed to update backup codes for user ${userId}: ${error instanceof Error ? error.message : 'Unknown error'}`,
        );
        return false;
      }
    }

    return false;
  }

  /**
   * 2FA 비활성화
   */
  async disableTwoFactor(
    userId: number,
    currentPassword: string,
  ): Promise<void> {
    const user = await this.userRepository.findOne({ where: { id: userId } });

    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    if (!user.isTwoFactorEnabled) {
      throw new BadRequestException('2FA가 활성화되어 있지 않습니다.');
    }

    // 현재 비밀번호 검증
    const isPasswordValid = await bcrypt.compare(
      currentPassword,
      user.password,
    );
    if (!isPasswordValid) {
      throw new BadRequestException('현재 비밀번호가 일치하지 않습니다.');
    }

    // 2FA 비활성화
    user.twoFactorSecret = null;
    user.isTwoFactorEnabled = false;
    user.backupCodes = null;
    await this.userRepository.save(user);
  }

  /**
   * 암호학적으로 안전한 백업 코드 생성
   */
  private generateBackupCodes(): string[] {
    const codes = new Set<string>();
    const maxAttempts = 30; // 최대 생성 시도 횟수
    let attempts = 0;

    while (
      codes.size < TWO_FACTOR_CONSTANTS.BACKUP_CODE_COUNT &&
      attempts < maxAttempts
    ) {
      attempts++;

      // 암호학적으로 안전한 엔트로피 생성 (128비트 = 16바이트)
      const entropy = randomBytes(16);

      // Base32 인코딩
      const base32Code = entropy
        .toString('base64')
        .replace(/[^A-HJ-KM-NP-TV-Z2-7]/gi, '') // 0,1,8,9,I,O 제외
        .toUpperCase()
        .substring(0, 12); // 12자리로 제한

      // 가독성을 위한 그룹화: XXXX-XXXX-XXXX 형태
      if (base32Code.length >= 12) {
        const formattedCode = `${base32Code.substring(0, 4)}-${base32Code.substring(4, 8)}-${base32Code.substring(8, 12)}`;
        codes.add(formattedCode);
      }
    }

    if (codes.size < TWO_FACTOR_CONSTANTS.BACKUP_CODE_COUNT) {
      this.logger.error(
        `Failed to generate sufficient backup codes. Generated: ${codes.size}, Required: ${TWO_FACTOR_CONSTANTS.BACKUP_CODE_COUNT}`,
      );
      throw new Error('백업 코드 생성에 실패했습니다.');
    }

    const codesArray = Array.from(codes);

    // 생성된 코드의 엔트로피 검증
    this.validateBackupCodeEntropy(codesArray);

    return codesArray;
  }

  /**
   * 백업 코드 엔트로피 검증
   * 생성된 코드들이 충분한 무작위성을 가지는지 검사
   */
  private validateBackupCodeEntropy(codes: string[]): void {
    // 최소 엔트로피 요구사항 검사
    const minUniqueChars = 8; // 최소 8개의 서로 다른 문자 필요
    const allChars = codes.join('').replace(/-/g, '');
    const uniqueChars = new Set(allChars).size;

    if (uniqueChars < minUniqueChars) {
      this.logger.warn(
        `Low entropy detected in backup codes. Unique chars: ${uniqueChars}, Required: ${minUniqueChars}`,
      );
      throw new Error('백업 코드의 무작위성이 부족합니다.');
    }

    // 코드 중복 검사 (정규화된 형태로)
    const normalizedCodes = codes.map((code) =>
      code.replace(/-/g, '').toUpperCase(),
    );
    const uniqueNormalizedCodes = new Set(normalizedCodes);

    if (uniqueNormalizedCodes.size !== codes.length) {
      this.logger.error('Duplicate backup codes detected');
      throw new Error('중복된 백업 코드가 감지되었습니다.');
    }

    this.logger.log(
      `Backup code entropy validation passed. Codes: ${codes.length}, Unique chars: ${uniqueChars}`,
    );
  }

  /**
   * 사용자 2FA 상태 확인
   */
  async getTwoFactorStatus(
    userId: number,
  ): Promise<{ enabled: boolean; hasBackupCodes: boolean }> {
    const user = await this.userRepository.findOne({ where: { id: userId } });

    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    // 2FA가 활성화되었지만 백업 코드가 없는 경우 자동 생성
    if (
      user.isTwoFactorEnabled &&
      (!user.backupCodes || user.backupCodes.length === 0)
    ) {
      this.logger.warn(
        `User ${userId} has 2FA enabled but no backup codes. Generating new ones.`,
      );

      const newBackupCodes = this.generateBackupCodes();
      const hashedBackupCodes = await Promise.all(
        newBackupCodes.map((code) => {
          const normalizedCode = code.replace(/-/g, '').toUpperCase();
          return bcrypt.hash(normalizedCode, 10);
        }),
      );

      await this.userRepository.update(userId, {
        backupCodes: hashedBackupCodes,
      });

      this.logger.log(
        `Generated ${newBackupCodes.length} backup codes for user ${userId}`,
      );
    }

    return {
      enabled: user.isTwoFactorEnabled,
      hasBackupCodes: !!(user.backupCodes && user.backupCodes.length > 0),
    };
  }
}
