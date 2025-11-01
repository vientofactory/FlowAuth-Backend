import {
  Controller,
  Post,
  Get,
  Body,
  Query,
  Request,
  Res,
  Logger,
  BadRequestException,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBody } from '@nestjs/swagger';
import type { Request as ExpressRequest, Response } from 'express';
import { OAuth2Service } from '../oauth2.service';
import { AuthorizationService } from '../services/authorization.service';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { AuthorizeRequestDto } from '../dto/oauth2.dto';
import { AuthorizeConsentDto } from '../dto/request.dto';
import { RedirectUrlResponseDto } from '../../common/dto/response.dto';
import { TOKEN_TYPES } from '../../constants/auth.constants';
import { OAUTH2_CONSTANTS } from '../../constants/oauth2.constants';
import { TokenUtils } from '../../utils/permission.util';
import type { User } from '../../auth/user.entity';

@Controller('oauth2')
@ApiTags('OAuth2 Flow')
export class ConsentController {
  private readonly logger = new Logger(ConsentController.name);

  constructor(
    private readonly oauth2Service: OAuth2Service,
    private readonly authorizationService: AuthorizationService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
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
    if (!authHeader?.startsWith('Bearer ')) {
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
      this.configService.get<string>('FRONTEND_URL') ?? 'http://localhost:5173';
    const backendUrl =
      this.configService.get<string>('BACKEND_URL') ?? 'http://localhost:3000';
    return `${frontendUrl}/auth/login?returnUrl=${encodeURIComponent(`${backendUrl}/oauth2/authorize?${params.toString()}`)}`;
  }

  private async handleAuthorizeFlow(
    user: User,
    authorizeDto: AuthorizeRequestDto,
    res: Response,
  ): Promise<void> {
    try {
      const result = await this.authorizationService.authorizeConsent(
        authorizeDto,
        user,
      );

      const redirectUrl = new URL(authorizeDto.redirect_uri);

      // response_type에 따른 리다이렉트 처리
      if (authorizeDto.response_type === OAUTH2_CONSTANTS.RESPONSE_TYPES.CODE) {
        // Authorization Code Grant: query parameter에 code 포함
        if (result.code) {
          redirectUrl.searchParams.set('code', result.code);
        }
        if (authorizeDto.state) {
          redirectUrl.searchParams.set('state', authorizeDto.state);
        }
      } else if (
        authorizeDto.response_type ===
        OAUTH2_CONSTANTS.RESPONSE_TYPES.CODE_ID_TOKEN
      ) {
        // Hybrid Flow: query parameter에 code, fragment에 id_token 포함
        if (result.code) {
          redirectUrl.searchParams.set('code', result.code);
        }
        if (authorizeDto.state) {
          redirectUrl.searchParams.set('state', authorizeDto.state);
        }

        const fragmentParams = new URLSearchParams();
        if (result.id_token) {
          fragmentParams.set('id_token', result.id_token);
        }
        if (authorizeDto.state) {
          fragmentParams.set('state', authorizeDto.state);
        }
        redirectUrl.hash = fragmentParams.toString();
      } else if (
        authorizeDto.response_type === OAUTH2_CONSTANTS.RESPONSE_TYPES.TOKEN ||
        authorizeDto.response_type ===
          OAUTH2_CONSTANTS.RESPONSE_TYPES.ID_TOKEN ||
        authorizeDto.response_type ===
          OAUTH2_CONSTANTS.RESPONSE_TYPES.TOKEN_ID_TOKEN
      ) {
        // Implicit Grant: fragment에 토큰 포함
        const fragmentParams = new URLSearchParams();

        if (result.access_token) {
          fragmentParams.set('access_token', result.access_token);
        }
        if (result.id_token) {
          fragmentParams.set('id_token', result.id_token);
        }
        if (result.token_type) {
          fragmentParams.set('token_type', result.token_type);
        }
        if (result.expires_in) {
          fragmentParams.set('expires_in', result.expires_in.toString());
        }
        if (authorizeDto.state) {
          fragmentParams.set('state', authorizeDto.state);
        }

        redirectUrl.hash = fragmentParams.toString();
      }

      res.redirect(redirectUrl.toString());
    } catch (error) {
      this.logger.error('Error in handleAuthorizeFlow', {
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

      res.redirect(redirectUrl.toString());
    }
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
      nonce: consentDto.nonce,
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
      redirectUrl.searchParams.set(
        'error',
        OAUTH2_CONSTANTS.ERRORS.ACCESS_DENIED,
      );
      redirectUrl.searchParams.set(
        'error_description',
        OAUTH2_CONSTANTS.ERROR_DESCRIPTIONS.ACCESS_DENIED,
      );

      if (authorizeDto.state) {
        redirectUrl.searchParams.set('state', authorizeDto.state);
      }

      return { redirect_url: redirectUrl.toString() };
    }

    // User approved consent, handle the OAuth2 flow
    try {
      const result = await this.authorizationService.authorizeConsent(
        authorizeDto,
        user,
      );

      const redirectUrl = new URL(authorizeDto.redirect_uri);

      // response_type에 따른 리다이렉트 URL 구성
      if (authorizeDto.response_type === OAUTH2_CONSTANTS.RESPONSE_TYPES.CODE) {
        // Authorization Code Grant: query parameter에 code 포함
        if (result.code) {
          redirectUrl.searchParams.set('code', result.code);
        }
        if (authorizeDto.state) {
          redirectUrl.searchParams.set('state', authorizeDto.state);
        }
      } else if (
        authorizeDto.response_type ===
        OAUTH2_CONSTANTS.RESPONSE_TYPES.CODE_ID_TOKEN
      ) {
        // Hybrid Flow: query parameter에 code, fragment에 id_token 포함
        if (result.code) {
          redirectUrl.searchParams.set('code', result.code);
        }
        if (authorizeDto.state) {
          redirectUrl.searchParams.set('state', authorizeDto.state);
        }

        const fragmentParams = new URLSearchParams();
        if (result.id_token) {
          fragmentParams.set('id_token', result.id_token);
        }
        if (authorizeDto.state) {
          fragmentParams.set('state', authorizeDto.state);
        }
        redirectUrl.hash = fragmentParams.toString();
      } else if (
        authorizeDto.response_type === OAUTH2_CONSTANTS.RESPONSE_TYPES.TOKEN ||
        authorizeDto.response_type ===
          OAUTH2_CONSTANTS.RESPONSE_TYPES.ID_TOKEN ||
        authorizeDto.response_type ===
          OAUTH2_CONSTANTS.RESPONSE_TYPES.TOKEN_ID_TOKEN
      ) {
        // Implicit Grant: fragment에 토큰 포함
        const fragmentParams = new URLSearchParams();

        if (result.access_token) {
          fragmentParams.set('access_token', result.access_token);
        }
        if (result.id_token) {
          fragmentParams.set('id_token', result.id_token);
        }
        if (result.token_type) {
          fragmentParams.set('token_type', result.token_type);
        }
        if (result.expires_in) {
          fragmentParams.set('expires_in', result.expires_in.toString());
        }
        if (authorizeDto.state) {
          fragmentParams.set('state', authorizeDto.state);
        }

        redirectUrl.hash = fragmentParams.toString();
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
}
