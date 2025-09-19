import { IsString, IsOptional, Length } from 'class-validator';

export class SetupTwoFactorDto {
  @IsOptional()
  @IsString()
  @Length(6, 6, { message: '2FA 코드는 6자리 숫자여야 합니다.' })
  token?: string;
}

export class VerifyTwoFactorDto {
  @IsString({ message: '2FA 토큰은 필수입니다.' })
  @Length(6, 6, { message: '2FA 코드는 6자리 숫자여야 합니다.' })
  token: string;
}

export class DisableTwoFactorDto {
  @IsString({ message: '현재 비밀번호는 필수입니다.' })
  currentPassword: string;

  @IsOptional()
  @IsString()
  @Length(6, 6, { message: '2FA 코드는 6자리 숫자여야 합니다.' })
  token?: string;
}

export class TwoFactorResponseDto {
  secret: string;
  qrCodeUrl: string;
  backupCodes: string[];
}

export class BackupCodeDto {
  @IsString({ message: '백업 코드는 필수입니다.' })
  code: string;
}
