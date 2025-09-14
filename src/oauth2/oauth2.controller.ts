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
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { JwtService } from '@nestjs/jwt';
import type { User } from '../user/user.entity';
import type { JwtPayload } from '../types/auth.types';
import {
  AuthorizeRequestDto,
  TokenRequestDto,
  TokenResponseDto,
  ErrorResponseDto,
} from './dto/oauth2.dto';

interface AuthenticatedRequest extends ExpressRequest {
  user: JwtPayload;
}

@Controller('oauth2')
export class OAuth2Controller {
  constructor(
    private readonly oauth2Service: OAuth2Service,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {}

  private async getAuthenticatedUser(
    req: ExpressRequest,
  ): Promise<User | null> {
    try {
      // Check cookie first - type-safe access
      const cookies = req.cookies as Record<string, unknown> | undefined;
      const cookieToken = cookies?.token;
      console.log(
        'OAuth2: Checking authentication, cookies:',
        Object.keys(cookies || {}),
      );
      console.log(
        'OAuth2: Token from cookie:',
        cookieToken ? 'present' : 'missing',
      );

      if (cookieToken && typeof cookieToken === 'string') {
        console.log('OAuth2: Attempting to verify token from cookie...');
        console.log('OAuth2: Token length:', cookieToken.length);
        console.log(
          'OAuth2: Token preview:',
          cookieToken.substring(0, 50) + '...',
        );

        try {
          // Add secret verification
          const secret =
            this.configService.get<string>('JWT_SECRET') || 'your-secret-key';
          console.log(
            'OAuth2: Using JWT secret:',
            secret.substring(0, 10) + '...',
          );
          console.log('OAuth2: Full JWT secret for comparison:', secret);

          // Decode token without verification to see its contents
          const tokenParts = cookieToken.split('.');
          if (tokenParts.length === 3) {
            try {
              const decodedPayload = JSON.parse(
                Buffer.from(tokenParts[1], 'base64').toString(),
              ) as {
                sub?: number;
                email?: string;
                iat?: number;
                exp?: number;
              };
              console.log('OAuth2: Token payload (without verification):', {
                sub: decodedPayload.sub,
                email: decodedPayload.email,
                iat: decodedPayload.iat,
                exp: decodedPayload.exp,
                issued: decodedPayload.iat
                  ? new Date(decodedPayload.iat * 1000).toISOString()
                  : 'unknown',
                expires: decodedPayload.exp
                  ? new Date(decodedPayload.exp * 1000).toISOString()
                  : 'unknown',
              });
            } catch (decodeError) {
              console.log(
                'OAuth2: Failed to decode token payload:',
                decodeError,
              );
            }
          }

          // Try manual verification with jwt library
          console.log('OAuth2: Attempting JWT verification...');
          const payload = this.jwtService.verify<JwtPayload>(cookieToken);
          console.log('OAuth2: Token verified successfully, payload:', {
            sub: payload.sub,
            exp: payload.exp,
          });
          const user = await this.oauth2Service.getUserInfo(payload.sub);
          console.log(
            'OAuth2: User found from cookie token:',
            user ? user.email : 'null',
          );
          return user;
        } catch (tokenError) {
          console.log(
            'OAuth2: Token verification failed:',
            tokenError instanceof Error
              ? tokenError.message
              : 'Unknown token error',
          );
          // Continue to check authorization header
        }
      }

      // Check Authorization header
      const authHeader = req.headers.authorization;
      console.log(
        'OAuth2: Authorization header:',
        authHeader ? 'present' : 'missing',
      );
      if (authHeader && authHeader.startsWith('Bearer ')) {
        console.log('OAuth2: Attempting to verify token from auth header...');
        try {
          const token = authHeader.substring(7);
          const payload = this.jwtService.verify<JwtPayload>(token);
          const user = await this.oauth2Service.getUserInfo(payload.sub);
          console.log(
            'OAuth2: User found from auth header:',
            user ? user.email : 'null',
          );
          return user;
        } catch (headerError) {
          console.log(
            'OAuth2: Auth header token verification failed:',
            headerError instanceof Error
              ? headerError.message
              : 'Unknown header token error',
          );
        }
      }

      console.log('OAuth2: No valid authentication found');
      return null;
    } catch (error) {
      console.log(
        'OAuth2: Authentication error:',
        error instanceof Error ? error.message : 'Unknown error',
      );
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
    // Validate basic OAuth2 parameters
    if (!authorizeDto.response_type || authorizeDto.response_type !== 'code') {
      const redirectUrl = new URL(authorizeDto.redirect_uri);
      redirectUrl.searchParams.set('error', 'unsupported_response_type');
      redirectUrl.searchParams.set(
        'error_description',
        'Response type must be "code"',
      );
      return res.redirect(redirectUrl.toString());
    }

    // Check if user is authenticated
    const user = await this.getAuthenticatedUser(req);

    if (!user) {
      // Redirect to login with return URL
      const loginUrl = this.buildLoginRedirectUrl(authorizeDto);
      return res.redirect(loginUrl);
    }

    // Check if this is a direct authorize call (no consent yet)
    // Redirect to consent page for user approval
    const consentUrl = this.buildConsentRedirectUrl(authorizeDto);
    return res.redirect(consentUrl);
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
  @UseGuards(JwtAuthGuard)
  async userinfo(@Request() req: AuthenticatedRequest): Promise<{
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
      roles: user.roles || [],
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
}
