import { Controller, Get, Logger, UsePipes } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { ConfigService } from '@nestjs/config';
import * as crypto from 'crypto';

@ApiTags('OpenID Connect JWKS')
@Controller('.well-known')
export class JwksController {
  private readonly logger = new Logger(JwksController.name);
  private jwk: any;

  constructor(private readonly configService: ConfigService) {
    // 애플리케이션 시작 시 JWK 생성 또는 환경 변수에서 로드
    this.initializeJWK();
  }

  private initializeJWK(): void {
    // 환경 변수에서 RSA 개인키 확인
    const privateKeyPem = this.configService.get<string>('RSA_PRIVATE_KEY');

    if (privateKeyPem) {
      try {
        // RSA 개인키에서 공개키 추출하여 JWK 생성
        const privateKey = crypto.createPrivateKey(privateKeyPem);
        const publicKey = crypto.createPublicKey(privateKey);
        const jwk = publicKey.export({ format: 'jwk' });

        this.jwk = {
          kty: jwk.kty,
          use: 'sig',
          kid: 'rsa-key-env',
          n: jwk.n,
          e: jwk.e,
          alg: 'RS256',
        };
      } catch (error) {
        this.logger.error(
          'Failed to initialize JWK from RSA_PRIVATE_KEY',
          error,
        );
        throw new Error(
          'Invalid RSA_PRIVATE_KEY configuration. Please ensure it contains a valid RSA private key.',
        );
      }
    } else {
      throw new Error(
        'RSA_PRIVATE_KEY environment variable is required. ' +
          'Run ./generate_rsa_keys.sh to generate a key pair and add RSA_PRIVATE_KEY to your .env file. ' +
          'NEVER commit private keys to version control.',
      );
    }
  }

  @Get('jwks.json')
  @UsePipes() // Disable global validation pipe for this endpoint
  @ApiOperation({
    summary: 'JSON Web Key Set',
    description: 'ID 토큰 검증에 필요한 공개키 정보를 제공합니다.',
  })
  @ApiResponse({
    status: 200,
    description: 'JWKS 정보',
  })
  getJwks() {
    try {
      const result = {
        keys: [this.jwk],
      };
      return result;
    } catch (error) {
      this.logger.error('Error generating JWKS:', error);
      throw error;
    }
  }
}
