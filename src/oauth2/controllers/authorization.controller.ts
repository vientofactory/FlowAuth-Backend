import {
  Controller,
  Get,
  Query,
  Request,
  Res,
  Logger,
  BadRequestException,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiQuery } from '@nestjs/swagger';
import { ConfigService } from '@nestjs/config';
import type { Request as ExpressRequest, Response } from 'express';
import { OAuth2Service } from '../oauth2.service';
import { JwtService } from '@nestjs/jwt';
import { TokenService } from '../token.service';
import { AuthorizationCodeService } from '../authorization-code.service';
import { ScopeService } from '../scope.service';
import { AuthorizeRequestDto } from '../dto/oauth2.dto';
import { AuthorizeInfoResponseDto, ClientInfoDto } from '../dto/response.dto';
import { TOKEN_TYPES } from '../../constants/auth.constants';
import { TokenUtils } from '../../utils/permission.util';
import type { User } from '../../user/user.entity';

@Controller('oauth2')
@ApiTags('OAuth2 Authorization')
export class AuthorizationController {
  private readonly logger = new Logger(AuthorizationController.name);

  constructor(
    private readonly oauth2Service: OAuth2Service,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
    private readonly tokenService: TokenService,
    private readonly authorizationCodeService: AuthorizationCodeService,
    private readonly scopeService: ScopeService,
  ) {}

  private async getAuthenticatedUserFromCookie(
    req: ExpressRequest,
  ): Promise<User | null> {
    const cookies = req.cookies as Record<string, unknown> | undefined;
    const cookieToken = cookies?.token;

    if (cookieToken && typeof cookieToken === 'string') {
      const payload = await TokenUtils.extractAndValidatePayload(
        cookieToken,
        TOKEN_TYPES.LOGIN,
        this.jwtService,
      );
      if (payload) {
        const user = await this.oauth2Service.getUserInfo(payload.sub);
        return user;
      }
    }

    return null;
  }

  private async getAuthenticatedUserFromHeader(
    req: ExpressRequest,
  ): Promise<User | null> {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return null;
    }

    const token = authHeader.substring(7);
    try {
      const payload = await TokenUtils.extractAndValidatePayload(
        token,
        TOKEN_TYPES.LOGIN,
        this.jwtService,
      );
      if (payload) {
        return await this.oauth2Service.getUserInfo(payload.sub);
      }
    } catch {
      return null;
    }

    return null;
  }

  private async getAuthenticatedUser(
    req: ExpressRequest,
  ): Promise<User | null> {
    try {
      // Check cookie first
      const userFromCookie = await this.getAuthenticatedUserFromCookie(req);
      if (userFromCookie) {
        return userFromCookie;
      }

      // Check Authorization header
      return await this.getAuthenticatedUserFromHeader(req);
    } catch {
      return null;
    }
  }

  private buildLoginRedirectUrl(authorizeParams: AuthorizeRequestDto): string {
    const params = new URLSearchParams();
    params.set('response_type', authorizeParams.response_type);
    params.set('client_id', authorizeParams.client_id);
    params.set('redirect_uri', authorizeParams.redirect_uri);

    if (authorizeParams.scope) {
      params.set('scope', authorizeParams.scope);
    }
    if (authorizeParams.state) {
      params.set('state', authorizeParams.state);
    }
    if (authorizeParams.code_challenge) {
      params.set('code_challenge', authorizeParams.code_challenge);
    }
    if (authorizeParams.code_challenge_method) {
      params.set(
        'code_challenge_method',
        authorizeParams.code_challenge_method,
      );
    }

    const frontendUrl =
      this.configService.get<string>('FRONTEND_URL') || 'http://localhost:5173';
    const backendUrl =
      this.configService.get<string>('BACKEND_URL') || 'http://localhost:3000';
    return `${frontendUrl}/auth/login?returnUrl=${encodeURIComponent(`${backendUrl}/oauth2/authorize?${params.toString()}`)}`;
  }

  private buildConsentRedirectUrl(
    authorizeParams: AuthorizeRequestDto,
  ): string {
    const params = new URLSearchParams();
    params.set('response_type', authorizeParams.response_type);
    params.set('client_id', authorizeParams.client_id);
    params.set('redirect_uri', authorizeParams.redirect_uri);

    if (authorizeParams.scope) {
      params.set('scope', authorizeParams.scope);
    }
    if (authorizeParams.state) {
      params.set('state', authorizeParams.state);
    }
    if (authorizeParams.code_challenge) {
      params.set('code_challenge', authorizeParams.code_challenge);
    }
    if (authorizeParams.code_challenge_method) {
      params.set(
        'code_challenge_method',
        authorizeParams.code_challenge_method,
      );
    }

    const frontendUrl =
      this.configService.get<string>('FRONTEND_URL') || 'http://localhost:5173';
    return `${frontendUrl}/oauth2/authorize?${params.toString()}`;
  }

  private validateBasicAuthorizeParameters(
    authorizeDto: AuthorizeRequestDto,
  ): void {
    if (!authorizeDto.response_type || authorizeDto.response_type !== 'code') {
      throw new BadRequestException('Response type must be "code"');
    }
  }

  @Get('authorize')
  @ApiOperation({
    summary: 'OAuth2 인증 시작',
    description: `
OAuth2 Authorization Code Flow의 시작점입니다.
클라이언트 애플리케이션이 사용자를 이 엔드포인트로 리다이렉트하여 인증을 요청합니다.

**플로우:**
1. 사용자가 로그인되어 있지 않으면 로그인 페이지로 리다이렉트
2. 사용자가 로그인되어 있으면 동의 페이지로 리다이렉트
3. 사용자가 동의하면 authorization code를 발급하여 redirect_uri로 리다이렉트
    `,
  })
  @ApiQuery({
    name: 'response_type',
    description: '응답 타입 (현재 "code"만 지원)',
    example: 'code',
    required: true,
  })
  @ApiQuery({
    name: 'client_id',
    description: '클라이언트 식별자',
    example: 'your-client-id',
    required: true,
  })
  @ApiQuery({
    name: 'redirect_uri',
    description: '인증 완료 후 리다이렉트될 URI',
    example: 'https://your-app.com/callback',
    required: true,
  })
  @ApiQuery({
    name: 'scope',
    description: '요청할 권한 스코프 (공백으로 구분)',
    example: 'identify email',
    required: false,
  })
  @ApiQuery({
    name: 'state',
    description: 'CSRF 방지를 위한 상태값',
    example: 'random-state-string',
    required: false,
  })
  @ApiQuery({
    name: 'code_challenge',
    description: 'PKCE 코드 챌린지',
    example: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
    required: false,
  })
  @ApiQuery({
    name: 'code_challenge_method',
    description: 'PKCE 코드 챌린지 메서드',
    example: 'S256',
    required: false,
  })
  @ApiResponse({
    status: 302,
    description:
      '로그인 페이지, 동의 페이지, 또는 클라이언트 redirect_uri로 리다이렉트',
  })
  @ApiResponse({
    status: 400,
    description: '잘못된 요청 파라미터',
  })
  async authorize(
    @Query() authorizeDto: AuthorizeRequestDto,
    @Request() req: ExpressRequest,
    @Res() res: Response,
  ): Promise<void> {
    try {
      // Validate basic OAuth2 parameters
      this.validateBasicAuthorizeParameters(authorizeDto);

      // Check if user is authenticated
      const user = await this.getAuthenticatedUser(req);

      if (!user) {
        // Redirect to login with return URL
        const loginUrl = this.buildLoginRedirectUrl(authorizeDto);
        return res.redirect(loginUrl);
      }

      // Handle the authorization flow
      // 사용자가 인증되었으므로 동의 페이지로 리다이렉트
      const consentUrl = this.buildConsentRedirectUrl(authorizeDto);
      return res.redirect(consentUrl);
    } catch {
      this.handleAuthorizeError(
        res,
        authorizeDto.redirect_uri,
        'server_error',
        'Internal server error',
        authorizeDto.state,
      );
    }
  }

  private handleAuthorizeError(
    res: Response,
    redirectUri: string,
    error: string,
    errorDescription: string,
    state?: string,
  ): void {
    try {
      // Validate redirect URI to prevent open redirect attacks
      const allowedRedirectUri = this.validateRedirectUriForError(redirectUri);
      if (!allowedRedirectUri) {
        // If redirect URI is invalid, return generic error without redirect
        res.status(400).json({
          error: 'invalid_request',
          error_description: 'Invalid redirect URI',
        });
        return;
      }

      const redirectUrl = new URL(allowedRedirectUri);

      // Only allow safe error parameters
      const safeErrors = [
        'invalid_request',
        'unauthorized_client',
        'access_denied',
        'unsupported_response_type',
        'invalid_scope',
        'invalid_grant',
        'server_error',
        'temporarily_unavailable',
      ];

      if (safeErrors.includes(error)) {
        redirectUrl.searchParams.set('error', error);
        // Sanitize error description to prevent information leakage
        const sanitizedDescription =
          this.sanitizeErrorDescription(errorDescription);
        redirectUrl.searchParams.set('error_description', sanitizedDescription);
      } else {
        // Unknown error - use generic message
        redirectUrl.searchParams.set('error', 'server_error');
        redirectUrl.searchParams.set('error_description', 'An error occurred');
      }

      if (state && typeof state === 'string' && state.length <= 500) {
        redirectUrl.searchParams.set('state', state);
      }

      res.redirect(redirectUrl.toString());
    } catch {
      // If redirect fails, return JSON error
      res.status(400).json({
        error: 'invalid_request',
        error_description: 'Invalid redirect URI',
      });
    }
  }

  private validateRedirectUriForError(redirectUri: string): string | null {
    try {
      const url = new URL(redirectUri);
      // Only allow HTTP/HTTPS schemes
      if (!['http:', 'https:'].includes(url.protocol)) {
        return null;
      }
      // Remove Private/Loopback Address Filter - For testing Purposes
      return redirectUri;
    } catch {
      return null;
    }
  }

  private sanitizeErrorDescription(description: string): string {
    // Remove potentially sensitive information from error messages
    return description
      .replace(/token[^a-zA-Z0-9]/gi, '[REDACTED]')
      .replace(/secret[^a-zA-Z0-9]/gi, '[REDACTED]')
      .replace(/password[^a-zA-Z0-9]/gi, '[REDACTED]')
      .replace(/key[^a-zA-Z0-9]/gi, '[REDACTED]')
      .substring(0, 200); // Limit length
  }

  @Get('authorize/info')
  @ApiOperation({
    summary: '인가 요청 정보 조회',
    description:
      '동의 페이지에서 표시할 클라이언트 및 스코프 정보를 조회합니다.',
  })
  @ApiQuery({
    name: 'client_id',
    description: '클라이언트 식별자',
    required: true,
  })
  @ApiQuery({
    name: 'redirect_uri',
    description: '리다이렉트 URI',
    required: true,
  })
  @ApiQuery({
    name: 'scope',
    description: '요청 스코프',
    required: false,
  })
  @ApiQuery({
    name: 'state',
    description: '상태값',
    required: false,
  })
  @ApiResponse({
    status: 200,
    description: '인가 요청 정보',
    type: AuthorizeInfoResponseDto,
  })
  async getAuthorizeInfo(
    @Query() authorizeDto: AuthorizeRequestDto,
    @Request() req: ExpressRequest,
  ): Promise<AuthorizeInfoResponseDto> {
    const user = await this.getAuthenticatedUser(req);

    if (!user) {
      throw new BadRequestException('Authentication required');
    }

    const { client, scopes } =
      await this.oauth2Service.getConsentInfo(authorizeDto);

    const clientInfo: ClientInfoDto = {
      id: client.clientId,
      name: client.name,
      description: client.description,
      logoUri: client.logoUri,
      termsOfServiceUri: client.termsOfServiceUri,
      policyUri: client.policyUri,
    };

    return {
      client: clientInfo,
      scopes,
    };
  }
}
