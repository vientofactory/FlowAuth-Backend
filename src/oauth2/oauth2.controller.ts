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
      if (cookieToken && typeof cookieToken === 'string') {
        const payload = this.jwtService.verify<JwtPayload>(cookieToken);
        return await this.oauth2Service.getUserInfo(payload.sub);
      }

      // Check Authorization header
      const authHeader = req.headers.authorization;
      if (authHeader && authHeader.startsWith('Bearer ')) {
        const token = authHeader.substring(7);
        const payload = this.jwtService.verify<JwtPayload>(token);
        return await this.oauth2Service.getUserInfo(payload.sub);
      }

      return null;
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

    // Handle the OAuth2 flow
    await this.handleAuthorizeFlow(user, authorizeDto, res);
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
