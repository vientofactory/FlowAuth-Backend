import {
  Controller,
  Post,
  Get,
  Body,
  Query,
  UseGuards,
  Request,
  BadRequestException,
} from '@nestjs/common';
import { Request as ExpressRequest } from 'express';
import { OAuth2Service } from './oauth2.service';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import {
  AuthorizeRequestDto,
  TokenRequestDto,
  TokenResponseDto,
  ErrorResponseDto,
} from './dto/oauth2.dto';

interface AuthenticatedRequest extends ExpressRequest {
  user: {
    sub: number;
    email: string;
    username: string;
    roles: string[];
  };
}

interface AuthenticatedRequest extends ExpressRequest {
  user: {
    sub: number;
    email: string;
    username: string;
    roles: string[];
  };
}

@Controller('oauth')
export class OAuth2Controller {
  constructor(private readonly oauth2Service: OAuth2Service) {}

  @Get('authorize')
  @UseGuards(JwtAuthGuard)
  async authorize(
    @Query() authorizeDto: AuthorizeRequestDto,
    @Request() req: AuthenticatedRequest,
  ): Promise<{ url: string }> {
    try {
      // Get user by ID from token
      const user = await this.oauth2Service.getUserInfo(req.user.sub);

      const result = (await this.oauth2Service.authorize(
        authorizeDto,
        user,
      )) as { code: string; state?: string; redirect_uri: string };

      // Redirect with authorization code
      const redirectUrl = new URL(authorizeDto.redirect_uri);
      redirectUrl.searchParams.append('code', result.code);

      if (result.state) {
        redirectUrl.searchParams.append('state', result.state);
      }

      return {
        url: redirectUrl.toString(),
      };
    } catch (error: unknown) {
      // Redirect with error
      const redirectUrl = new URL(authorizeDto.redirect_uri);
      redirectUrl.searchParams.append('error', 'server_error');
      redirectUrl.searchParams.append(
        'error_description',
        error instanceof Error ? error.message : 'Unknown error',
      );

      if (authorizeDto.state) {
        redirectUrl.searchParams.append('state', authorizeDto.state);
      }

      return {
        url: redirectUrl.toString(),
      };
    }
  }

  @Post('token')
  async token(
    @Body() tokenDto: TokenRequestDto,
  ): Promise<TokenResponseDto | ErrorResponseDto> {
    try {
      const result = await this.oauth2Service.token(tokenDto);
      return result;
    } catch (error: unknown) {
      throw new BadRequestException({
        error: 'invalid_request',
        error_description:
          error instanceof Error ? error.message : 'Unknown error',
      });
    }
  }

  @Get('userinfo')
  @UseGuards(JwtAuthGuard)
  userinfo(@Request() req: AuthenticatedRequest): {
    sub: number;
    email: string;
    username: string;
    roles: string[];
  } {
    return {
      sub: req.user.sub,
      email: req.user.email,
      username: req.user.username,
      roles: req.user.roles,
    };
  }
}
