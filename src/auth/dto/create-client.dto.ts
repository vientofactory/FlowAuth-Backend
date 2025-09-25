import { IsNotEmpty, IsString, IsArray, IsOptional } from 'class-validator';
import { Trim, Escape } from 'class-sanitizer';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class CreateClientDto {
  @ApiProperty({
    description: '클라이언트 이름',
    example: 'My App',
  })
  @IsString()
  @IsNotEmpty()
  @Trim()
  @Escape()
  name: string;

  @ApiPropertyOptional({
    description: '클라이언트 설명',
    example: 'My OAuth2 application',
  })
  @IsString()
  @IsOptional()
  @Trim()
  @Escape()
  description?: string;

  @ApiProperty({
    description: '리다이렉트 URI 목록',
    example: ['https://myapp.com/callback', 'https://myapp.com/auth/callback'],
    type: [String],
  })
  @IsArray()
  @IsString({ each: true })
  redirectUris: string[];

  @ApiProperty({
    description: '허용된 권한 부여 타입 목록',
    example: ['authorization_code', 'refresh_token'],
    type: [String],
  })
  @IsArray()
  @IsString({ each: true })
  grants: string[];

  @ApiProperty({
    description: '허용된 스코프 목록',
    example: ['read:user', 'read:profile', 'basic'],
    type: [String],
  })
  @IsArray()
  @IsString({ each: true })
  scopes: string[];

  @ApiPropertyOptional({
    description: '클라이언트 로고 URL',
    example: 'https://myapp.com/logo.png',
  })
  @IsString()
  @IsOptional()
  logoUri?: string;

  @ApiPropertyOptional({
    description: '이용약관 URL',
    example: 'https://myapp.com/terms',
  })
  @IsString()
  @IsOptional()
  termsOfServiceUri?: string;

  @ApiPropertyOptional({
    description: '개인정보처리방침 URL',
    example: 'https://myapp.com/privacy',
  })
  @IsString()
  @IsOptional()
  policyUri?: string;

  @ApiProperty({
    description: 'reCAPTCHA 토큰',
    example: 'recaptcha_token_here',
  })
  @IsString()
  @IsNotEmpty()
  recaptchaToken: string;
}
