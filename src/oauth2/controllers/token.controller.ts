import {
  Controller,
  Post,
  Body,
  Logger,
  BadRequestException,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBody } from '@nestjs/swagger';
import { OAuth2Service } from '../oauth2.service';
import { TokenRequestDto, TokenResponseDto } from '../dto/oauth2.dto';
import { ErrorResponseDto } from '../../common/dto/response.dto';
import {
  mapExceptionToOAuth2Error,
  createOAuth2Error,
} from '../utils/oauth2-error.util';

@Controller('oauth2')
@ApiTags('OAuth2 Token')
export class TokenController {
  private readonly logger = new Logger(TokenController.name);

  constructor(private readonly oauth2Service: OAuth2Service) {}

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
}
