import {
  Controller,
  Post,
  Get,
  Body,
  Query,
  UseGuards,
  Request,
  BadRequestException,
  Res,
  Logger,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiQuery,
  ApiBody,
  ApiBearerAuth,
} from '@nestjs/swagger';
import { ConfigService } from '@nestjs/config';
import {
  UserinfoResponseDto,
  AuthorizeInfoResponseDto,
  ClientInfoDto,
} from './dto/response.dto';
import { AuthorizeConsentDto } from './dto/request.dto';
import {
  RedirectUrlResponseDto,
  ErrorResponseDto,
} from '../common/dto/response.dto';
import type { Request as ExpressRequest, Response } from 'express';
import { OAuth2Service } from './oauth2.service';
import { OAuth2BearerGuard } from './guards/oauth2-bearer.guard';
import { OAuth2ScopeGuard } from './guards/oauth2-scope.guard';
import { RequireScopes } from './decorators/require-scopes.decorator';
import { TokenService } from './token.service';
import { AuthorizationCodeService } from './authorization-code.service';
import { ScopeService } from './scope.service';
import { JwtService } from '@nestjs/jwt';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import {
  PermissionsGuard,
  RequirePermissions,
} from '../auth/permissions.guard';
import { PERMISSIONS, TOKEN_TYPES } from '../constants/auth.constants';
import type { User } from '../user/user.entity';
import type { OAuth2JwtPayload } from '../types/oauth2.types';
import { PermissionUtils, TokenUtils } from '../utils/permission.util';
import {
  mapExceptionToOAuth2Error,
  createOAuth2Error,
} from '../utils/oauth2-error.util';
import {
  AuthorizeRequestDto,
  TokenRequestDto,
  TokenResponseDto,
} from './dto/oauth2.dto';

interface OAuth2AuthenticatedRequest extends ExpressRequest {
  user: OAuth2JwtPayload;
}

@Controller('oauth2')
@ApiTags('OAuth2 Flow')
export class OAuth2Controller {
  private readonly logger = new Logger(OAuth2Controller.name);

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
    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.substring(7);
      const payload = await TokenUtils.extractAndValidatePayload(
        token,
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

  private async handleAuthorizeFlow(
    user: User,
    authorizeDto: AuthorizeRequestDto,
    res: Response,
  ): Promise<void> {
    try {
      const result = await this.oauth2Service.authorize(authorizeDto, user);

      const redirectUrl = new URL(authorizeDto.redirect_uri);
      redirectUrl.searchParams.set('code', result.code);

      if (authorizeDto.state) {
        redirectUrl.searchParams.set('state', authorizeDto.state);
      }

      res.redirect(redirectUrl.toString());
    } catch {
      const redirectUrl = new URL(authorizeDto.redirect_uri);
      redirectUrl.searchParams.set('error', 'server_error');
      redirectUrl.searchParams.set(
        'error_description',
        'Internal server error',
      );

      if (authorizeDto.state) {
        redirectUrl.searchParams.set('state', authorizeDto.state);
      }

      res.redirect(redirectUrl.toString());
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
    example: 'openid profile email',
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

  private validateBasicAuthorizeParameters(
    authorizeDto: AuthorizeRequestDto,
  ): void {
    if (!authorizeDto.response_type || authorizeDto.response_type !== 'code') {
      throw new BadRequestException('Response type must be "code"');
    }
  }

  private async handleAuthorizationFlowWithConsent(
    authorizeDto: AuthorizeRequestDto,
    res: Response,
    req: ExpressRequest,
  ): Promise<void> {
    // For now, directly handle the authorization without consent page
    // TODO: Implement proper consent flow
    try {
      // Get authenticated user
      const user = await this.getAuthenticatedUser(req);
      if (!user) {
        throw new Error('User not authenticated');
      }

      await this.handleAuthorizeFlow(user, authorizeDto, res);
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

  @Post('token')
  @ApiOperation({
    summary: 'OAuth2 토큰 발급',
    description: `
Authorization Code를 사용하여 Access Token을 발급받습니다.

**요구사항:**
- Authorization Code (authorize 엔드포인트에서 발급받은 코드)
- Client 인증 정보
- PKCE를 사용한 경우 code_verifier

**반환되는 토큰:**
- access_token: API 접근용 JWT 토큰
- refresh_token: 토큰 갱신용 토큰
- expires_in: 토큰 만료 시간 (초)
    `,
  })
  @ApiBody({
    type: TokenRequestDto,
    description: '토큰 요청 데이터',
  })
  @ApiResponse({
    status: 200,
    description: '토큰 발급 성공',
    type: TokenResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: '잘못된 요청 또는 유효하지 않은 authorization code',
    type: ErrorResponseDto,
  })
  async token(
    @Body() tokenDto: TokenRequestDto,
  ): Promise<TokenResponseDto | ErrorResponseDto> {
    try {
      if (tokenDto.grant_type !== 'authorization_code') {
        return {
          error: 'unsupported_grant_type',
          error_description: 'Grant type must be "authorization_code"',
        };
      }

      return await this.oauth2Service.token(tokenDto);
    } catch (error) {
      // Convert exceptions to OAuth2 standard error responses
      if (error instanceof BadRequestException) {
        return mapExceptionToOAuth2Error(error);
      }

      // For unexpected errors
      this.logger.error('Unexpected error in token endpoint', error);
      return createOAuth2Error('server_error', 'An unexpected error occurred');
    }
  }

  @Get('userinfo')
  @UseGuards(OAuth2BearerGuard, OAuth2ScopeGuard)
  @RequireScopes('identify')
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({
    summary: '사용자 정보 조회',
    description: `
OAuth2 Access Token을 사용하여 사용자 정보를 조회합니다.

**스코프별 반환 정보:**
- 기본: sub (사용자 식별자)
- identify 스코프: 사용자명, 역할 정보
- email 스코프: 이메일 주소

**필요한 스코프:** identify
    `,
  })
  @ApiResponse({
    status: 200,
    description: '사용자 정보',
    type: UserinfoResponseDto,
  })
  @ApiResponse({
    status: 401,
    description: '유효하지 않은 토큰',
  })
  @ApiResponse({
    status: 403,
    description: '권한 부족 (스코프 부족)',
  })
  async userinfo(
    @Request() req: OAuth2AuthenticatedRequest,
  ): Promise<UserinfoResponseDto> {
    if (req.user.sub === null) {
      throw new BadRequestException('User ID not available for this token');
    }

    const user = await this.oauth2Service.getUserInfo(req.user.sub);

    if (!user) {
      throw new BadRequestException('User not found');
    }

    // 토큰의 스코프에 따라 반환할 정보를 결정
    // OAuth2JwtPayload의 scopes 속성은 string[] 타입
    const userScopes: string[] = req.user.scopes || [];

    const response: {
      sub: string;
      email?: string;
      username?: string;
      roles?: string[];
    } = {
      sub: user.id.toString(), // 기본적으로 항상 포함 (OpenID Connect 표준)
    };

    // email 스코프가 있을 때만 이메일 반환
    if (userScopes.includes('email')) {
      response.email = user.email;
    }

    // identify 스코프가 있을 때만 프로필 정보 반환
    if (userScopes.includes('identify')) {
      response.username = user.username;
      response.roles = [PermissionUtils.getRoleName(user.permissions)];
    }

    return response;
  }

  @Get('authorize/info')
  @ApiOperation({
    summary: 'OAuth2 동의 정보 조회',
    description: `
OAuth2 인증 동의 화면에 표시할 클라이언트 및 스코프 정보를 조회합니다.

**요구사항:**
- 사용자가 로그인되어 있어야 함
- 유효한 OAuth2 매개변수들이 쿼리 파라미터로 포함되어야 함

**반환 정보:**
- 클라이언트 정보 (이름, 설명, 로고 등)
- 요청된 스코프 목록
    `,
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
    name: 'response_type',
    description: '응답 타입 (현재 "code"만 지원)',
    example: 'code',
    required: true,
  })
  @ApiQuery({
    name: 'scope',
    description: '요청할 권한 스코프 (공백으로 구분)',
    example: 'openid profile email',
    required: false,
  })
  @ApiResponse({
    status: 200,
    description: '동의 정보 조회 성공',
    type: AuthorizeInfoResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: '잘못된 요청 파라미터',
  })
  @ApiResponse({
    status: 401,
    description: '인증 필요',
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

  @Post('authorize/consent')
  @ApiOperation({
    summary: 'OAuth2 인증 동의 처리',
    description: `
사용자의 OAuth2 인증 동의를 처리합니다.

**요구사항:**
- 사용자가 로그인되어 있어야 함
- 유효한 OAuth2 매개변수들과 동의 여부가 body에 포함되어야 함
    `,
  })
  @ApiBody({
    type: AuthorizeConsentDto,
    description: '사용자 동의 정보 및 OAuth2 매개변수',
  })
  @ApiResponse({
    status: 200,
    description: '동의 처리 완료 - 리다이렉트 URL 반환',
    type: RedirectUrlResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: '잘못된 요청 - 필수 매개변수 누락 또는 잘못된 값',
  })
  @ApiResponse({
    status: 401,
    description: '인증 필요',
  })
  async authorizeConsent(
    @Body() consentDto: AuthorizeConsentDto,
    @Request() req: ExpressRequest,
  ): Promise<RedirectUrlResponseDto> {
    this.logger.log(
      `Consent request received: client_id=${consentDto.client_id}, approved=${consentDto.approved}, scope=${consentDto.scope}`,
    );

    const user = await this.getAuthenticatedUser(req);

    if (!user) {
      throw new BadRequestException('Authentication required');
    }

    // Convert consent data to AuthorizeRequestDto for processing
    const authorizeDto: AuthorizeRequestDto = {
      client_id: consentDto.client_id!,
      redirect_uri: consentDto.redirect_uri!,
      response_type: consentDto.response_type!,
      scope: consentDto.scope,
      state: consentDto.state!,
      code_challenge: consentDto.code_challenge,
      code_challenge_method: consentDto.code_challenge_method,
    };

    // Validate required fields
    if (
      !authorizeDto.client_id ||
      !authorizeDto.redirect_uri ||
      !authorizeDto.response_type
    ) {
      throw new BadRequestException('Missing required OAuth2 parameters');
    }

    if (!consentDto.approved) {
      // User denied consent
      const redirectUrl = new URL(authorizeDto.redirect_uri);
      redirectUrl.searchParams.set('error', 'access_denied');
      redirectUrl.searchParams.set(
        'error_description',
        'User denied the request',
      );

      if (authorizeDto.state) {
        redirectUrl.searchParams.set('state', authorizeDto.state);
      }

      return { redirect_url: redirectUrl.toString() };
    }

    // User approved consent, handle the OAuth2 flow
    try {
      const result = await this.oauth2Service.authorize(authorizeDto, user);

      const redirectUrl = new URL(authorizeDto.redirect_uri);
      redirectUrl.searchParams.set('code', result.code);

      if (authorizeDto.state) {
        redirectUrl.searchParams.set('state', authorizeDto.state);
      }

      return { redirect_url: redirectUrl.toString() };
    } catch (error) {
      this.logger.error('Error in authorizeConsent', {
        error: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : undefined,
      });
      const redirectUrl = new URL(authorizeDto.redirect_uri);
      redirectUrl.searchParams.set('error', 'server_error');
      redirectUrl.searchParams.set(
        'error_description',
        'Internal server error',
      );

      if (authorizeDto.state) {
        redirectUrl.searchParams.set('state', authorizeDto.state);
      }

      return { redirect_url: redirectUrl.toString() };
    }
  }

  @Get('consent')
  async consent(
    @Query() authorizeDto: AuthorizeRequestDto,
    @Request() req: ExpressRequest,
    @Res() res: Response,
  ): Promise<void> {
    const user = await this.getAuthenticatedUser(req);

    if (!user) {
      const loginUrl = this.buildLoginRedirectUrl(authorizeDto);
      return res.redirect(loginUrl);
    }

    // For now, automatically approve consent
    await this.handleAuthorizeFlow(user, authorizeDto, res);
  }

  @Post('cleanup')
  async cleanupExpiredData() {
    const deletedTokens = await this.tokenService.cleanupExpiredTokens();
    const deletedCodes =
      await this.authorizationCodeService.cleanupExpiredCodes();

    return {
      message: 'Cleanup completed',
      deletedTokens,
      deletedCodes,
    };
  }

  @Get('scopes')
  @ApiTags('OAuth2 Flow')
  @ApiOperation({
    summary: '사용 가능한 스코프 목록 조회',
    description: `
시스템에 정의된 모든 OAuth2 스코프의 목록을 조회합니다.

**용도:**
- 클라이언트 개발자가 사용 가능한 스코프 확인
- OAuth2 테스터에서 동적 스코프 선택
    `,
  })
  @ApiResponse({
    status: 200,
    description: '스코프 목록과 메타 정보',
    schema: {
      type: 'object',
      properties: {
        scopes: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              name: {
                type: 'string',
                description: '스코프 이름',
                example: 'identify',
              },
              description: {
                type: 'string',
                description: '스코프 설명',
                example: '계정의 기본 정보 읽기 (사용자 ID, 이름 등)',
              },
              isDefault: {
                type: 'boolean',
                description: '기본 스코프 여부',
                example: false,
              },
            },
          },
        },
        meta: {
          type: 'object',
          properties: {
            total: {
              type: 'number',
              description: '전체 스코프 수',
              example: 19,
            },
            cached: {
              type: 'boolean',
              description: '캐시 사용 여부',
              example: true,
            },
            cacheSize: {
              type: 'number',
              description: '캐시에 저장된 스코프 수',
              example: 19,
            },
          },
        },
      },
    },
  })
  async getAvailableScopes() {
    const scopes = await this.scopeService.findAll();
    const cacheInfo = this.scopeService.getCacheInfo();

    return {
      scopes: scopes.map((scope) => ({
        name: scope.name,
        description: scope.description,
        isDefault: scope.isDefault,
      })),
      meta: {
        total: scopes.length,
        cached: cacheInfo.initialized,
        cacheSize: cacheInfo.cacheSize,
      },
    };
  }

  @Post('scopes/refresh')
  @UseGuards(JwtAuthGuard, PermissionsGuard)
  @RequirePermissions(PERMISSIONS.MANAGE_SYSTEM)
  async refreshScopesCache(@Request() req: ExpressRequest) {
    // JWT 토큰에서 사용자 정보 추출
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) {
      throw new BadRequestException('Authorization token required');
    }

    const payload = await TokenUtils.extractAndValidatePayload(
      token,
      TOKEN_TYPES.LOGIN,
      this.jwtService,
    );
    if (!payload) {
      throw new BadRequestException('Invalid token');
    }

    // 사용자 정보 조회
    const user = await this.oauth2Service.getUserInfo(payload.sub);
    if (!user) {
      throw new BadRequestException('User not found');
    }

    await this.scopeService.refreshCache();
    const cacheInfo = this.scopeService.getCacheInfo();

    return {
      message: 'Scopes cache refreshed successfully',
      cacheInfo,
    };
  }

  @Get('scopes/cache-info')
  @UseGuards(JwtAuthGuard, PermissionsGuard)
  @RequirePermissions(PERMISSIONS.MANAGE_SYSTEM)
  async getScopesCacheInfo(@Request() req: ExpressRequest) {
    // JWT 토큰에서 사용자 정보 추출
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) {
      throw new BadRequestException('Authorization token required');
    }

    const payload = await TokenUtils.extractAndValidatePayload(
      token,
      TOKEN_TYPES.LOGIN,
      this.jwtService,
    );
    if (!payload) {
      throw new BadRequestException('Invalid token');
    }

    // 사용자 정보 조회
    const user = await this.oauth2Service.getUserInfo(payload.sub);
    if (!user) {
      throw new BadRequestException('User not found');
    }

    // 시스템 관리자 권한 확인
    if (!PermissionUtils.isAdmin(user.permissions)) {
      throw new BadRequestException('System administrator privileges required');
    }

    return this.scopeService.getCacheInfo();
  }
}
