import { IsString, IsEmail, IsNumber, Min, Max } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class GeneralSettingsDto {
  @ApiProperty({
    description: '사이트 이름',
    example: 'FlowAuth',
  })
  @IsString()
  siteName: string;

  @ApiProperty({
    description: '사이트 설명',
    example: 'OAuth2 인증 시스템',
  })
  @IsString()
  siteDescription: string;

  @ApiProperty({
    description: '관리자 이메일',
    example: 'admin@flowauth.com',
  })
  @IsEmail()
  adminEmail: string;

  @ApiProperty({
    description: '기본 액세스 토큰 만료 시간 (초)',
    example: 86400,
    minimum: 300,
    maximum: 2592000,
  })
  @IsNumber()
  @Min(300)
  @Max(2592000)
  defaultTokenExpiry: number;

  @ApiProperty({
    description: '기본 리프레시 토큰 만료 시간 (초)',
    example: 2592000,
    minimum: 86400,
    maximum: 31536000,
  })
  @IsNumber()
  @Min(86400)
  @Max(31536000)
  defaultRefreshTokenExpiry: number;
}
