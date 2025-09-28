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
import { User } from '../user/user.entity';
import { TwoFactorResponseDto } from './dto/2fa/two-factor.dto';
import {
  AUTH_ERROR_MESSAGES,
  TWO_FACTOR_CONSTANTS,
} from '../constants/auth.constants';
import * as bcrypt from 'bcrypt';
import { randomBytes } from 'crypto';

// 타입 선언 추가
interface SpeakeasySecret {
  base32: string;
  otpauth_url: string;
}

interface SpeakeasyTotp {
  verify(options: {
    secret: string;
    encoding: string;
    token: string;
    window: number;
  }): boolean;
}

interface SpeakeasyTotpModule {
  totp: SpeakeasyTotp;
  generateSecret(options: {
    name: string;
    issuer: string;
    length: number;
  }): SpeakeasySecret;
}

interface QRCodeModule {
  toDataURL(text: string): Promise<string>;
}

@Injectable()
export class TwoFactorService {
  private readonly logger = new Logger(TwoFactorService.name);

  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
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
    const speakeasyModule = speakeasy as unknown as SpeakeasyTotpModule;
    const secret = speakeasyModule.generateSecret({
      name: `FlowAuth:${user.username}`,
      issuer: 'FlowAuth',
      length: TWO_FACTOR_CONSTANTS.SECRET_LENGTH,
    });

    // 백업 코드 생성 (10개)
    const backupCodes = this.generateBackupCodes();

    // QR 코드 URL 생성
    const qrCodeModule = QRCode as unknown as QRCodeModule;
    const qrCodeUrl = await qrCodeModule.toDataURL(secret.otpauth_url);

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
    const speakeasyModule = speakeasy as unknown as SpeakeasyTotpModule;
    const isValid = speakeasyModule.totp.verify({
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
  }

  /**
   * 2FA 토큰 검증
   */
  async verifyToken(userId: number, token: string): Promise<boolean> {
    const user = await this.userRepository.findOne({ where: { id: userId } });

    if (!user || !user.twoFactorSecret) {
      return false;
    }

    if (!user.isTwoFactorEnabled) {
      throw new UnauthorizedException(
        AUTH_ERROR_MESSAGES.TWO_FACTOR_NOT_ENABLED,
      );
    }

    const speakeasyModule = speakeasy as unknown as SpeakeasyTotpModule;
    return speakeasyModule.totp.verify({
      secret: user.twoFactorSecret,
      encoding: 'base32',
      token: token,
      window: 2,
    });
  }

  /**
   * 백업 코드 검증
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

    // 입력된 코드를 대문자로 변환하고 하이픈 제거
    const normalizedInputCode = code.replace(/-/g, '').toUpperCase();

    // 백업 코드 검증
    for (let i = 0; i < user.backupCodes.length; i++) {
      try {
        // 해시된 백업 코드와 입력된 코드를 직접 비교
        const isValid = await bcrypt.compare(
          normalizedInputCode,
          user.backupCodes[i],
        );
        if (isValid) {
          // 사용된 백업 코드는 제거
          const updatedBackupCodes = [...user.backupCodes];
          updatedBackupCodes.splice(i, 1);

          await this.userRepository.update(userId, {
            backupCodes: updatedBackupCodes,
          });

          return true;
        }
      } catch {
        // bcrypt 비교 실패 시 다음 코드로 진행
        continue;
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
    await this.userRepository.update(userId, {
      twoFactorSecret: undefined,
      isTwoFactorEnabled: false,
      backupCodes: undefined,
    });
  }

  /**
   * 백업 코드 생성
   */
  private generateBackupCodes(): string[] {
    const codes: string[] = [];
    for (let i = 0; i < TWO_FACTOR_CONSTANTS.BACKUP_CODE_COUNT; i++) {
      // 8자리 16진수 코드 생성 (XXXX-XXXX 형식) - 암호학적으로 안전한 난수 사용
      const randomHex = randomBytes(4).toString('hex').toUpperCase();
      const part1 = randomHex.substring(0, 4);
      const part2 = randomHex.substring(4, 8);
      const code = `${part1}-${part2}`;
      codes.push(code);
    }
    return codes;
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
