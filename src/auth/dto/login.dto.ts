import { IsEmail, IsNotEmpty, IsString } from 'class-validator';
import { Trim, Escape } from 'class-sanitizer';
import { ApiProperty } from '@nestjs/swagger';

export class LoginDto {
  @ApiProperty({
    description: '이메일 주소',
    example: 'john@example.com',
  })
  @IsEmail()
  @Trim()
  @Escape()
  email: string;

  @ApiProperty({
    description: '비밀번호',
    example: 'password123',
  })
  @IsString()
  @IsNotEmpty()
  @Trim()
  password: string;

  @ApiProperty({
    description: 'reCAPTCHA 토큰',
    example: 'recaptcha_token_here',
  })
  @IsString()
  @IsNotEmpty()
  @Trim()
  @Escape()
  recaptchaToken: string;
}
