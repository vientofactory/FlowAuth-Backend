import { ApiProperty } from '@nestjs/swagger';
import {
  IsBoolean,
  IsString,
  IsOptional,
  IsIn,
  Length,
  Matches,
} from 'class-validator';
import { Trim, Escape } from 'class-sanitizer';
import { OAUTH2_CONSTANTS } from '../../constants/oauth2.constants';

/**
 * OAuth2 인증 동의 요청 DTO
 */
export class AuthorizeConsentDto {
  @ApiProperty({
    description: '사용자의 동의 여부',
    example: true,
  })
  @IsBoolean()
  approved: boolean;

  @ApiProperty({
    description: '클라이언트 ID',
    example: 'my-client-app',
    maxLength: 100,
  })
  @IsString({ message: 'client_id must be a string' })
  @IsOptional()
  @Length(1, OAUTH2_CONSTANTS.CLIENT_ID_MAX_LENGTH, {
    message: `client_id must be between 1 and ${OAUTH2_CONSTANTS.CLIENT_ID_MAX_LENGTH} characters`,
  })
  @Trim()
  @Escape()
  client_id?: string;

  @ApiProperty({
    description: '리다이렉트 URI',
    example: 'https://client.example.com/callback',
    maxLength: 2048,
  })
  @IsString({ message: 'redirect_uri must be a string' })
  @IsOptional()
  @Length(1, OAUTH2_CONSTANTS.REDIRECT_URI_MAX_LENGTH, {
    message: `redirect_uri must be between 1 and ${OAUTH2_CONSTANTS.REDIRECT_URI_MAX_LENGTH} characters`,
  })
  @Trim()
  redirect_uri?: string;

  @ApiProperty({
    description: '응답 타입',
    example: 'code',
    enum: ['code', 'token', 'id_token', 'code id_token', 'token id_token'],
  })
  @IsString({ message: 'response_type must be a string' })
  @IsOptional()
  @IsIn(['code', 'token', 'id_token', 'code id_token', 'token id_token'], {
    message: 'Invalid response_type',
  })
  response_type?: string;

  @ApiProperty({
    description: '요청 스코프',
    example: 'openid profile email',
    required: false,
    maxLength: 500,
  })
  @IsString({ message: 'scope must be a string' })
  @IsOptional()
  @Length(0, OAUTH2_CONSTANTS.SCOPE_MAX_LENGTH, {
    message: `scope must not exceed ${OAUTH2_CONSTANTS.SCOPE_MAX_LENGTH} characters`,
  })
  @Trim()
  @Escape()
  scope?: string;

  @ApiProperty({
    description: 'CSRF 방지를 위한 상태 값',
    example: 'xyz789',
    required: false,
    maxLength: 256,
  })
  @IsString({ message: 'state must be a string' })
  @IsOptional()
  @Length(0, OAUTH2_CONSTANTS.STATE_MAX_LENGTH, {
    message: `state must not exceed ${OAUTH2_CONSTANTS.STATE_MAX_LENGTH} characters`,
  })
  @Trim()
  @Escape()
  state?: string;

  @ApiProperty({
    description: 'PKCE 코드 챌린지',
    example: 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
    required: false,
  })
  @IsString({ message: 'code_challenge must be a string' })
  @IsOptional()
  @Matches(OAUTH2_CONSTANTS.PKCE_UNRESERVED_CHAR_PATTERN, {
    message: 'code_challenge contains invalid characters',
  })
  @Trim()
  code_challenge?: string;

  @ApiProperty({
    description: 'PKCE 코드 챌린지 방법',
    example: 'S256',
    enum: ['plain', 'S256'],
    required: false,
  })
  @IsString({ message: 'code_challenge_method must be a string' })
  @IsOptional()
  @IsIn(['plain', 'S256'], {
    message:
      'code_challenge_method must be one of the following values: plain, S256',
  })
  code_challenge_method?: string;

  @ApiProperty({
    description: 'OIDC nonce 값',
    example: 'n-0S6_WzA2Mj',
    required: false,
    maxLength: 256,
  })
  @IsString({ message: 'nonce must be a string' })
  @IsOptional()
  @Length(0, OAUTH2_CONSTANTS.NONCE_MAX_LENGTH, {
    message: `nonce must not exceed ${OAUTH2_CONSTANTS.NONCE_MAX_LENGTH} characters`,
  })
  @Trim()
  @Escape()
  nonce?: string;
}
