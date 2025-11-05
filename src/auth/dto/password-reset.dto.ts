import { IsEmail, IsString, MinLength, MaxLength } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class RequestPasswordResetDto {
  @ApiProperty({
    description: '비밀번호 재설정을 요청할 이메일 주소',
    example: 'user@example.com',
  })
  @IsEmail({}, { message: '올바른 이메일 형식이 아닙니다.' })
  email: string;
}

export class ResetPasswordDto {
  @ApiProperty({
    description: '비밀번호 재설정 토큰',
    example: 'abcd1234efgh5678...',
  })
  @IsString({ message: '토큰은 문자열이어야 합니다.' })
  @MinLength(32, { message: '토큰이 올바르지 않습니다.' })
  @MaxLength(128, { message: '토큰이 올바르지 않습니다.' })
  token: string;

  @ApiProperty({
    description:
      '새로운 비밀번호 (최소 8자, 영문 대소문자, 숫자, 특수문자 포함)',
    example: 'NewP@ssw0rd123',
  })
  @IsString({ message: '비밀번호는 문자열이어야 합니다.' })
  @MinLength(8, { message: '비밀번호는 최소 8자 이상이어야 합니다.' })
  @MaxLength(128, { message: '비밀번호는 최대 128자까지 입력 가능합니다.' })
  newPassword: string;
}
