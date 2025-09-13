import { IsString, IsOptional, IsIn, IsNotEmpty } from 'class-validator';

export class AuthorizeRequestDto {
  @IsString()
  @IsNotEmpty()
  client_id: string;

  @IsString()
  @IsNotEmpty()
  redirect_uri: string;

  @IsString()
  @IsIn(['code', 'token'])
  response_type: string;

  @IsString()
  @IsOptional()
  scope?: string;

  @IsString()
  @IsOptional()
  state?: string;

  @IsString()
  @IsOptional()
  code_challenge?: string;

  @IsString()
  @IsOptional()
  @IsIn(['plain', 'S256'])
  code_challenge_method?: string;
}

export class TokenRequestDto {
  @IsString()
  @IsNotEmpty()
  @IsIn(['authorization_code', 'refresh_token', 'client_credentials'])
  grant_type: string;

  @IsString()
  @IsNotEmpty()
  client_id: string;

  @IsString()
  @IsOptional()
  client_secret?: string;

  @IsString()
  @IsOptional()
  code?: string;

  @IsString()
  @IsOptional()
  redirect_uri?: string;

  @IsString()
  @IsOptional()
  code_verifier?: string;

  @IsString()
  @IsOptional()
  refresh_token?: string;

  @IsString()
  @IsOptional()
  scope?: string;
}

export class AuthorizeResponseDto {
  code: string;
  state?: string;
  redirect_uri: string;
}

export class TokenResponseDto {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token?: string;
  scope?: string;
}

export class ErrorResponseDto {
  error: string;
  error_description?: string;
  error_uri?: string;
  state?: string;
}
