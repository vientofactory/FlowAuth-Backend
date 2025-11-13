import {
  Controller,
  Get,
  InternalServerErrorException,
  Logger,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import {
  DiscoveryService,
  OIDCDiscoveryDocument,
} from '../services/discovery.service';

@ApiTags('OpenID Connect')
@Controller('.well-known')
export class DiscoveryController {
  private readonly logger = new Logger(DiscoveryController.name);

  constructor(private readonly discoveryService: DiscoveryService) {}

  @Get('openid-configuration')
  @ApiOperation({
    summary: 'OpenID Connect Discovery',
    description: 'OpenID Provider 메타데이터를 제공합니다.',
  })
  @ApiResponse({
    status: 200,
    description: 'OpenID Connect 설정 정보',
    schema: {
      type: 'object',
      properties: {
        issuer: {
          type: 'string',
          description: '발급자 식별자',
          example: 'https://auth.example.com',
        },
        authorization_endpoint: {
          type: 'string',
          description: '인증 엔드포인트',
          example: 'https://auth.example.com/oauth2/authorize',
        },
        token_endpoint: {
          type: 'string',
          description: '토큰 엔드포인트',
          example: 'https://auth.example.com/oauth2/token',
        },
        userinfo_endpoint: {
          type: 'string',
          description: '사용자 정보 엔드포인트',
          example: 'https://auth.example.com/oauth2/userinfo',
        },
        jwks_uri: {
          type: 'string',
          description: 'JWKS 엔드포인트',
          example: 'https://auth.example.com/.well-known/jwks.json',
        },
        scopes_supported: {
          type: 'array',
          items: { type: 'string' },
          description: '지원하는 스코프 목록',
          example: ['openid', 'profile', 'email'],
        },
        response_types_supported: {
          type: 'array',
          items: { type: 'string' },
          description: '지원하는 응답 타입 목록',
          example: [
            'code',
            'token',
            'id_token',
            'code id_token',
            'token id_token',
          ],
        },
        grant_types_supported: {
          type: 'array',
          items: { type: 'string' },
          description: '지원하는 Grant 타입 목록',
          example: [
            'authorization_code',
            'refresh_token',
            'client_credentials',
          ],
        },
        claims_supported: {
          type: 'array',
          items: { type: 'string' },
          description: '지원하는 클레임 목록',
          example: [
            'sub',
            'name',
            'given_name',
            'family_name',
            'email',
            'email_verified',
            'preferred_username',
            'profile',
            'picture',
            'updated_at',
            'roles',
          ],
        },
      },
    },
  })
  @ApiResponse({
    status: 500,
    description: '서버 오류로 인해 Discovery Document 생성 실패',
  })
  async getOpenIdConfiguration(): Promise<OIDCDiscoveryDocument> {
    try {
      return await this.discoveryService.generateDiscoveryDocument();
    } catch (error) {
      this.logger.error('Error generating OpenID Configuration:', error);

      // 서비스에서 이미 적절한 예외를 던지므로 그대로 재던짐
      if (error instanceof InternalServerErrorException) {
        throw error;
      }

      // 예상치 못한 오류인 경우
      throw new InternalServerErrorException(
        'Failed to generate OpenID Configuration',
      );
    }
  }
}
