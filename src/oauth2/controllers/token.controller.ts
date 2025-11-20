import {
  Controller,
  Post,
  Body,
  Logger,
  BadRequestException,
  Headers,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBody } from '@nestjs/swagger';
import { TokenGrantService } from '../services/token-grant.service';
import { TokenIntrospectionService } from '../services/token-introspection.service';
import { TokenRequestDto, TokenResponseDto } from '../dto/oauth2.dto';
import { ProblemDetailsDto } from '../../common/dto/response.dto';
import {
  AdvancedRateLimitGuard,
  RateLimit,
} from '../../common/guards/advanced-rate-limit.guard';
import { DefaultFieldSizeLimitPipe } from '../../common/middleware/size-limit.middleware';
import { RATE_LIMIT_CONFIGS } from '../../constants/security.constants';
import { UseGuards } from '@nestjs/common';

@Controller('oauth2')
@UseGuards(AdvancedRateLimitGuard)
@ApiTags('OAuth2 Flow')
export class TokenController {
  private readonly logger = new Logger(TokenController.name);

  constructor(
    private readonly tokenGrantService: TokenGrantService,
    private readonly tokenIntrospectionService: TokenIntrospectionService,
  ) {}

  @Post('token')
  @RateLimit(RATE_LIMIT_CONFIGS.OAUTH2_TOKEN)
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
    type: ProblemDetailsDto,
  })
  async token(
    @Body(DefaultFieldSizeLimitPipe) tokenDto: TokenRequestDto,
    @Headers('authorization') authHeader?: string,
  ): Promise<TokenResponseDto> {
    // Parse Basic Authentication header if present
    let clientId = tokenDto.client_id;
    let clientSecret = tokenDto.client_secret;

    if (authHeader?.startsWith('Basic ')) {
      try {
        const base64Credentials = authHeader.substring(6);
        const credentials = Buffer.from(base64Credentials, 'base64').toString(
          'utf8',
        );
        const [headerClientId, headerClientSecret] = credentials.split(':');

        // Use credentials from header if not provided in body
        clientId ??= headerClientId;
        clientSecret ??= headerClientSecret;
      } catch (error) {
        this.logger.warn('Failed to parse Authorization header', error);
        throw new BadRequestException({
          error: 'invalid_client',
          error_description: 'Invalid Authorization header format',
        });
      }
    }

    // Validate required client_id (optional for refresh_token grant per RFC 6749)
    if (!clientId && tokenDto.grant_type !== 'refresh_token') {
      throw new BadRequestException({
        error: 'invalid_request',
        error_description: 'client_id is required',
      });
    }

    // Create a new request object with extracted credentials
    const enhancedTokenDto = {
      ...tokenDto,
      client_id: clientId,
      client_secret: clientSecret,
    };

    return await this.tokenGrantService.token(enhancedTokenDto);
  }

  @Post('introspect')
  @ApiOperation({
    summary: '토큰 인트로스펙션',
    description: `
토큰의 유효성을 검사하고 메타데이터를 반환합니다.

**지원되는 토큰 타입:**
- access_token: 액세스 토큰 검증
- id_token: ID 토큰 검증 (OIDC)
- refresh_token: 리프레시 토큰 검증

**인증 요구사항:**
- Basic Authentication (Client ID/Secret)
- Bearer Token Authentication

**반환 정보:**
- active: 토큰 유효성
- client_id: 클라이언트 ID
- exp: 만료 시간
- iat: 발급 시간
- sub: 사용자 ID (액세스 토큰의 경우)
- scope: 권한 범위
- token_type: 토큰 타입
    `,
  })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        token: {
          type: 'string',
          description: '검증할 토큰',
        },
        token_type_hint: {
          type: 'string',
          enum: ['access_token', 'id_token', 'refresh_token'],
          description: '토큰 타입 힌트 (선택사항)',
        },
      },
      required: ['token'],
    },
  })
  @ApiResponse({
    status: 200,
    schema: {
      type: 'object',
      properties: {
        active: { type: 'boolean' },
        client_id: { type: 'string' },
        exp: { type: 'number' },
        iat: { type: 'number' },
        sub: { type: 'string' },
        scope: { type: 'string' },
        token_type: { type: 'string' },
        username: { type: 'string' },
      },
    },
  })
  @ApiResponse({
    status: 401,
    description: '인증 실패',
  })
  async introspect(@Body() body: { token: string; token_type_hint?: string }) {
    try {
      return await this.tokenIntrospectionService.introspectToken(
        body.token,
        body.token_type_hint,
      );
    } catch (error) {
      this.logger.error('Token introspection failed', error);
      return { active: false };
    }
  }
}
