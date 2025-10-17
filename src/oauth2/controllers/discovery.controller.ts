import { Controller, Get, Logger, UsePipes } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { ConfigService } from '@nestjs/config';

@ApiTags('OpenID Connect Discovery')
@Controller('.well-known')
export class DiscoveryController {
  private readonly logger = new Logger(DiscoveryController.name);

  constructor(private readonly configService: ConfigService) {}

  @Get('openid-configuration')
  @UsePipes() // Disable global validation pipe for this endpoint
  @ApiOperation({
    summary: 'OpenID Connect Discovery',
    description: 'OpenID Provider의 메타데이터를 제공합니다.',
  })
  @ApiResponse({
    status: 200,
    description: 'OpenID Connect 설정 정보',
  })
  getOpenIdConfiguration() {
    try {
      const baseUrl =
        this.configService.get<string>('BACKEND_URL') ||
        'http://localhost:3000';

      const configuration = {
        issuer: baseUrl,
        authorization_endpoint: `${baseUrl}/oauth2/authorize`,
        token_endpoint: `${baseUrl}/oauth2/token`,
        userinfo_endpoint: `${baseUrl}/oauth2/userinfo`,
        jwks_uri: `${baseUrl}/.well-known/jwks.json`,
        scopes_supported: ['openid', 'profile', 'email'],
        response_types_supported: ['code', 'id_token', 'code id_token'],
        grant_types_supported: [
          'authorization_code',
          'refresh_token',
          'client_credentials',
        ],
        subject_types_supported: ['public'],
        id_token_signing_alg_values_supported: ['RS256'],
        token_endpoint_auth_methods_supported: [
          'client_secret_basic',
          'client_secret_post',
        ],
        claims_supported: [
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
        ],
        request_parameter_supported: false,
        request_uri_parameter_supported: false,
        require_request_uri_registration: false,
      };

      return configuration;
    } catch (error) {
      this.logger.error('Error generating OpenID Configuration:', error);
      throw error;
    }
  }
}
