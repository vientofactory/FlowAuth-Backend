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
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { Request as ExpressRequest, Response } from 'express';
import { OAuth2Service } from './oauth2.service';
import { OAuth2BearerGuard } from './oauth2-bearer.guard';
import { TokenService } from './token.service';
import { AuthorizationCodeService } from './authorization-code.service';
import { JwtService } from '@nestjs/jwt';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import type { User } from '../user/user.entity';
import type { JwtPayload } from '../types/auth.types';
import { PermissionUtils } from '../utils/permission.util';
import {
  AuthorizeRequestDto,
  TokenRequestDto,
  TokenResponseDto,
  ErrorResponseDto,
} from './dto/oauth2.dto';

interface AuthenticatedRequest extends ExpressRequest {
  user: User;
}

interface OAuth2AuthenticatedRequest extends ExpressRequest {
  user: JwtPayload;
}

@Controller('oauth2')
export class OAuth2Controller {
  constructor(
    private readonly oauth2Service: OAuth2Service,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
    private readonly tokenService: TokenService,
    private readonly authorizationCodeService: AuthorizationCodeService,
  ) {}

  private async getAuthenticatedUserFromCookie(
    req: ExpressRequest,
  ): Promise<User | null> {
    const cookies = req.cookies as Record<string, unknown> | undefined;
    const cookieToken = cookies?.token;

    if (cookieToken && typeof cookieToken === 'string') {
      try {
        const payload = this.jwtService.verify<JwtPayload>(cookieToken);
        const user = await this.oauth2Service.getUserInfo(payload.sub);
        return user;
      } catch {
        // Continue to check authorization header
      }
    }

    return null;
  }

  private async getAuthenticatedUserFromHeader(
    req: ExpressRequest,
  ): Promise<User | null> {
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      try {
        const token = authHeader.substring(7);
        const payload = this.jwtService.verify<JwtPayload>(token);
        const user = await this.oauth2Service.getUserInfo(payload.sub);
        return user;
      } catch {
        // Token verification failed
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
      await this.handleAuthorizationFlowWithConsent(authorizeDto, res);
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

  // eslint-disable-next-line @typescript-eslint/require-await
  private async handleAuthorizationFlowWithConsent(
    authorizeDto: AuthorizeRequestDto,
    res: Response,
  ): Promise<void> {
    // Check if this is a direct authorize call (no consent yet)
    // Redirect to consent page for user approval
    const consentUrl = this.buildConsentRedirectUrl(authorizeDto);
    res.redirect(consentUrl);
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
      // Prevent localhost/private IP redirects in production
      if (process.env.NODE_ENV === 'production') {
        const hostname = url.hostname.toLowerCase();
        if (
          hostname === 'localhost' ||
          hostname === '127.0.0.1' ||
          hostname.startsWith('192.168.') ||
          hostname.startsWith('10.') ||
          hostname.startsWith('172.')
        ) {
          return null;
        }
      }
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
  async token(
    @Body() tokenDto: TokenRequestDto,
  ): Promise<TokenResponseDto | ErrorResponseDto> {
    if (tokenDto.grant_type !== 'authorization_code') {
      return {
        error: 'unsupported_grant_type',
        error_description: 'Grant type must be "authorization_code"',
      };
    }

    return await this.oauth2Service.token(tokenDto);
  }

  @Get('userinfo')
  @UseGuards(OAuth2BearerGuard)
  async userinfo(@Request() req: OAuth2AuthenticatedRequest): Promise<{
    sub: string;
    email: string;
    username: string;
    roles: string[];
  }> {
    const user = await this.oauth2Service.getUserInfo(req.user.sub);

    if (!user) {
      throw new BadRequestException('User not found');
    }

    return {
      sub: user.id.toString(),
      email: user.email,
      username: user.username,
      roles: [PermissionUtils.getRoleName(user.permissions)],
    };
  }

  @Get('authorize/info')
  async getAuthorizeInfo(
    @Query() authorizeDto: AuthorizeRequestDto,
    @Request() req: ExpressRequest,
  ): Promise<{ client: any; scopes: string[] }> {
    const user = await this.getAuthenticatedUser(req);

    if (!user) {
      throw new BadRequestException('Authentication required');
    }

    const { client, scopes } =
      await this.oauth2Service.getConsentInfo(authorizeDto);

    return {
      client: {
        id: client.clientId,
        name: client.name,
        description: client.description,
        logoUri: client.logoUri,
        termsOfServiceUri: client.termsOfServiceUri,
        policyUri: client.policyUri,
      },
      scopes,
    };
  }

  @Post('authorize/consent')
  async authorizeConsent(
    @Body() consentDto: AuthorizeRequestDto & { approved: boolean },
    @Request() req: ExpressRequest,
  ): Promise<{ redirect_url: string }> {
    const user = await this.getAuthenticatedUser(req);

    if (!user) {
      throw new BadRequestException('Authentication required');
    }

    if (!consentDto.approved) {
      // User denied consent
      const redirectUrl = new URL(consentDto.redirect_uri);
      redirectUrl.searchParams.set('error', 'access_denied');
      redirectUrl.searchParams.set(
        'error_description',
        'User denied the request',
      );

      if (consentDto.state) {
        redirectUrl.searchParams.set('state', consentDto.state);
      }

      return { redirect_url: redirectUrl.toString() };
    }

    // User approved consent, handle the OAuth2 flow
    try {
      const result = await this.oauth2Service.authorize(consentDto, user);

      const redirectUrl = new URL(consentDto.redirect_uri);
      redirectUrl.searchParams.set('code', result.code);

      if (consentDto.state) {
        redirectUrl.searchParams.set('state', consentDto.state);
      }

      return { redirect_url: redirectUrl.toString() };
    } catch {
      const redirectUrl = new URL(consentDto.redirect_uri);
      redirectUrl.searchParams.set('error', 'server_error');
      redirectUrl.searchParams.set(
        'error_description',
        'Internal server error',
      );

      if (consentDto.state) {
        redirectUrl.searchParams.set('state', consentDto.state);
      }

      return { redirect_url: redirectUrl.toString() };
    }
  }

  @Get('dashboard/stats')
  @UseGuards(JwtAuthGuard)
  async getDashboardStats(@Request() req: AuthenticatedRequest): Promise<{
    totalClients: number;
    activeTokens: number;
    lastLoginDate: Date | null;
    accountCreated: Date | null;
  }> {
    const user = req.user;

    // Get total clients count for this user
    const totalClients = await this.oauth2Service.getTotalClientsCount(user.id);

    // Get active tokens count for this user
    const activeTokens = await this.oauth2Service.getActiveTokensCount(user.id);

    return {
      totalClients,
      activeTokens,
      lastLoginDate: null, // TODO: Add lastLoginAt field to User entity
      accountCreated: user.createdAt || null,
    };
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
}
