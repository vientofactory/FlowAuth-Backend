import {
  IsString,
  IsOptional,
  IsIn,
  IsNotEmpty,
  Length,
  Matches,
} from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
import { OAUTH2_CONSTANTS } from '../../constants/oauth2.constants';
import { IsPKCEConsistent } from '../validators/pkce.validator';
import { IsValidGrantTypeFields } from '../validators/grant-type.validator';
import { IsValidPKCEFormat } from '../validators/pkce-format.validator';

export class AuthorizeRequestDto {
  @ApiProperty({
    description: '클라이언트 ID',
    example: 'my-client-app',
    maxLength: 100,
  })
  @IsString({ message: 'client_id must be a string' })
  @IsNotEmpty({ message: 'client_id should not be empty' })
  @Length(1, OAUTH2_CONSTANTS.CLIENT_ID_MAX_LENGTH, {
    message: `client_id must be between 1 and ${OAUTH2_CONSTANTS.CLIENT_ID_MAX_LENGTH} characters`,
  })
  client_id: string;

  @ApiProperty({
    description: '리다이렉트 URI',
    example: 'https://client.example.com/callback',
    maxLength: 2048,
  })
  @IsString({ message: 'redirect_uri must be a string' })
  @IsNotEmpty({ message: 'redirect_uri should not be empty' })
  @Length(1, OAUTH2_CONSTANTS.REDIRECT_URI_MAX_LENGTH, {
    message: `redirect_uri must be between 1 and ${OAUTH2_CONSTANTS.REDIRECT_URI_MAX_LENGTH} characters`,
  })
  redirect_uri: string;

  @ApiProperty({
    description: '응답 타입',
    example: 'code',
    enum: ['code', 'token', 'id_token', 'code id_token', 'token id_token'],
  })
  @IsString({ message: 'response_type must be a string' })
  @IsIn(['code', 'token', 'id_token', 'code id_token', 'token id_token'], {
    message:
      'response_type must be one of: code, token, id_token, code id_token, token id_token',
  })
  response_type: string;

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
  @IsString()
  // Custom validation will be implemented in the service layer for scope validation
  scope?: string;

  @ApiProperty({
    description: 'CSRF 방지를 위한 상태 값 (보안상 권장)',
    example: 'xyz789',
    required: false,
    maxLength: 256,
  })
  @IsString({ message: 'state must be a string' })
  @IsOptional()
  @Length(1, OAUTH2_CONSTANTS.STATE_MAX_LENGTH, {
    message: `state must be between 1 and ${OAUTH2_CONSTANTS.STATE_MAX_LENGTH} characters`,
  })
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
  @IsPKCEConsistent()
  @IsValidPKCEFormat()
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
    description: 'OIDC nonce 값 (ID Token 재사용 방지)',
    example: 'n-0S6_WzA2Mj',
    required: false,
    maxLength: 256,
  })
  @IsString({ message: 'nonce must be a string' })
  @IsOptional()
  @Length(1, OAUTH2_CONSTANTS.NONCE_MAX_LENGTH, {
    message: `nonce must be between 1 and ${OAUTH2_CONSTANTS.NONCE_MAX_LENGTH} characters`,
  })
  nonce?: string;
}

export class AuthorizeConsentQueryDto {
  @ApiProperty({
    description: '클라이언트 ID',
    example: 'my-client-app',
    required: false,
  })
  @IsString({ message: 'client_id must be a string' })
  @IsOptional()
  client_id?: string;

  @ApiProperty({
    description: '리다이렉트 URI',
    example: 'https://client.example.com/callback',
    required: false,
  })
  @IsString({ message: 'redirect_uri must be a string' })
  @IsOptional()
  redirect_uri?: string;

  @ApiProperty({
    description: '응답 타입',
    example: 'code',
    enum: ['code', 'token'],
    required: false,
  })
  @IsString({ message: 'response_type must be a string' })
  @IsOptional()
  @IsIn(['code', 'token', 'id_token', 'code id_token', 'token id_token'], {
    message:
      'response_type must be one of: code, token, id_token, code id_token, token id_token',
  })
  response_type?: string;

  @ApiProperty({
    description: '요청 스코프',
    example: 'openid profile email',
    required: false,
  })
  @IsString({ message: 'scope must be a string' })
  @IsOptional()
  scope?: string;

  @ApiProperty({
    description: 'CSRF 방지를 위한 상태 값',
    example: 'xyz789',
    required: false,
  })
  @IsString({ message: 'state must be a string' })
  @IsOptional()
  state?: string;

  @ApiProperty({
    description: 'PKCE 코드 챌린지',
    example: 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
    required: false,
  })
  @IsString({ message: 'code_challenge must be a string' })
  @IsOptional()
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
}

export class TokenRequestDto {
  @ApiProperty({
    description: '권한 부여 타입',
    example: 'authorization_code',
    enum: ['authorization_code', 'refresh_token', 'client_credentials'],
  })
  @IsString({ message: 'grant_type must be a string' })
  @IsNotEmpty({ message: 'grant_type should not be empty' })
  @IsIn(['authorization_code', 'refresh_token', 'client_credentials'], {
    message:
      'grant_type must be one of the following values: authorization_code, refresh_token, client_credentials',
  })
  @IsValidGrantTypeFields()
  grant_type: string;

  @ApiProperty({
    description: '클라이언트 ID',
    example: 'my-client-app',
    maxLength: 100,
    required: false,
  })
  @IsString({ message: 'client_id must be a string' })
  @IsOptional()
  @Length(1, OAUTH2_CONSTANTS.CLIENT_ID_MAX_LENGTH, {
    message: `client_id must be between 1 and ${OAUTH2_CONSTANTS.CLIENT_ID_MAX_LENGTH} characters`,
  })
  client_id?: string;

  @ApiProperty({
    description: '클라이언트 시크릿',
    example: 'client-secret-123',
    required: false,
  })
  @IsString({ message: 'client_secret must be a string' })
  @IsOptional()
  client_secret?: string;

  @ApiProperty({
    description: '인증 코드',
    example: 'abc123',
    required: false,
    maxLength: 100,
  })
  @IsString({ message: 'code must be a string' })
  @IsOptional()
  @Length(0, OAUTH2_CONSTANTS.AUTHORIZATION_CODE_MAX_LENGTH, {
    message: `code must not exceed ${OAUTH2_CONSTANTS.AUTHORIZATION_CODE_MAX_LENGTH} characters`,
  })
  code?: string;

  @ApiProperty({
    description: '리다이렉트 URI',
    example: 'https://client.example.com/callback',
    required: false,
    maxLength: 2048,
  })
  @IsString({ message: 'redirect_uri must be a string' })
  @IsOptional()
  @Length(0, OAUTH2_CONSTANTS.REDIRECT_URI_MAX_LENGTH, {
    message: `redirect_uri must not exceed ${OAUTH2_CONSTANTS.REDIRECT_URI_MAX_LENGTH} characters`,
  })
  redirect_uri?: string;

  @ApiProperty({
    description: 'PKCE 코드 베리파이어',
    example: 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
    required: false,
    maxLength: 128,
  })
  @IsString({ message: 'code_verifier must be a string' })
  @IsOptional()
  @Length(0, OAUTH2_CONSTANTS.CODE_VERIFIER_MAX_LENGTH, {
    message: `code_verifier must not exceed ${OAUTH2_CONSTANTS.CODE_VERIFIER_MAX_LENGTH} characters`,
  })
  @Matches(OAUTH2_CONSTANTS.PKCE_UNRESERVED_CHAR_PATTERN, {
    message: 'code_verifier contains invalid characters',
  })
  code_verifier?: string;

  @ApiProperty({
    description: '리프레시 토큰',
    example: 'refresh-token-123',
    required: false,
    maxLength: 500,
  })
  @IsString({ message: 'refresh_token must be a string' })
  @IsOptional()
  @Length(0, OAUTH2_CONSTANTS.REFRESH_TOKEN_MAX_LENGTH, {
    message: `refresh_token must not exceed ${OAUTH2_CONSTANTS.REFRESH_TOKEN_MAX_LENGTH} characters`,
  })
  refresh_token?: string;

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
  scope?: string;
}

export class AuthorizeResponseDto {
  @ApiProperty({
    description: '인증 코드 (Authorization Code Grant)',
    example: 'auth_code_123',
    required: false,
  })
  code?: string;

  @ApiProperty({
    description: '액세스 토큰 (Implicit Grant)',
    example: 'access_token_123',
    required: false,
  })
  access_token?: string;

  @ApiProperty({
    description: 'ID 토큰 (Implicit Grant)',
    example: 'id_token_123',
    required: false,
  })
  id_token?: string;

  @ApiProperty({
    description: '토큰 타입 (Implicit Grant)',
    example: 'Bearer',
    required: false,
  })
  token_type?: string;

  @ApiProperty({
    description: '토큰 만료 시간 (초) (Implicit Grant)',
    example: 3600,
    required: false,
  })
  expires_in?: number;

  @ApiProperty({
    description: '상태 값',
    example: 'xyz789',
    required: false,
  })
  state?: string;

  @ApiProperty({
    description: '리다이렉트 URI',
    example: 'https://client.example.com/callback',
  })
  redirect_uri: string;
}

export class TokenResponseDto {
  @ApiProperty({
    description: '액세스 토큰',
    example: 'access_token_123',
  })
  access_token: string;

  @ApiProperty({
    description: '토큰 타입',
    example: 'Bearer',
  })
  token_type: string;

  @ApiProperty({
    description: '토큰 만료 시간 (초)',
    example: 3600,
  })
  expires_in: number;

  @ApiProperty({
    description: '리프레시 토큰',
    example: 'refresh_token_123',
    required: false,
  })
  refresh_token?: string;

  @ApiProperty({
    description: '부여된 스코프',
    example: 'openid profile email',
    required: false,
  })
  scope?: string;

  @ApiProperty({
    description: 'ID 토큰 (OpenID Connect)',
    example: 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...',
    required: false,
  })
  id_token?: string;
}

export class ErrorResponseDto {
  @ApiProperty({
    description: '에러 코드',
    example: 'invalid_request',
  })
  error: string;

  @ApiProperty({
    description: '에러 설명',
    example: 'The request is missing a required parameter',
    required: false,
  })
  error_description?: string;

  @ApiProperty({
    description: '에러 관련 URI',
    example: 'https://example.com/error',
    required: false,
  })
  error_uri?: string;

  @ApiProperty({
    description: '상태 값',
    example: 'xyz789',
    required: false,
  })
  state?: string;
}
