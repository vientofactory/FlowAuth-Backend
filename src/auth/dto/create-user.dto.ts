import {
  IsEmail,
  IsNotEmpty,
  IsString,
  MinLength,
  IsOptional,
  IsEnum,
} from 'class-validator';
import { Trim, Escape } from 'class-sanitizer';
import { ApiProperty } from '@nestjs/swagger';
import { USER_TYPES } from '../../constants/auth.constants';

export class CreateUserDto {
  @ApiProperty({
    description: '사용자 이름',
    example: 'john_doe',
  })
  @IsString()
  @IsNotEmpty()
  @Trim()
  @Escape()
  username: string;

  @ApiProperty({
    description: '이메일 주소',
    example: 'john@example.com',
  })
  @IsEmail()
  @Trim()
  @Escape()
  email: string;

  @ApiProperty({
    description: '비밀번호 (최소 8자)',
    example: 'password123',
    minLength: 8,
  })
  @IsString()
  @MinLength(8)
  @Trim()
  password: string;

  @ApiProperty({
    description: '이름',
    example: 'John',
  })
  @IsString()
  @IsNotEmpty()
  @Trim()
  @Escape()
  firstName: string;

  @ApiProperty({
    description: '성',
    example: 'Doe',
  })
  @IsString()
  @IsNotEmpty()
  @Trim()
  @Escape()
  lastName: string;

  @ApiProperty({
    description: '사용자 유형',
    example: USER_TYPES.REGULAR,
    enum: USER_TYPES,
    required: false,
  })
  @IsOptional()
  @IsEnum(USER_TYPES)
  userType?: USER_TYPES;

  @ApiProperty({
    description: 'reCAPTCHA 토큰',
    example: 'recaptcha_token_here',
  })
  @IsString()
  @IsNotEmpty()
  recaptchaToken: string;
}
