import { Controller, Get } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { ConfigService } from '@nestjs/config';
import * as crypto from 'crypto';

@ApiTags('OpenID Connect JWKS')
@Controller('.well-known')
export class JwksController {
  private jwk: any;

  constructor(private readonly configService: ConfigService) {
    // 애플리케이션 시작 시 JWK 생성 또는 환경 변수에서 로드
    this.initializeJWK();
  }

  private initializeJWK(): void {
    // 환경 변수에서 RSA 공개키 확인
    const publicKeyPem = this.configService.get<string>('RSA_PUBLIC_KEY');
    const privateKeyPem = this.configService.get<string>('RSA_PRIVATE_KEY');

    if (publicKeyPem && privateKeyPem) {
      // 환경 변수에서 키 로드
      try {
        const publicKey = crypto.createPublicKey(publicKeyPem);
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
        console.error('Failed to load RSA key from environment:', error);
        this.generateFallbackJWK();
      }
    } else {
      // 개발용 키 생성
      this.generateFallbackJWK();
    }
  }

  private generateFallbackJWK(): void {
    // 개발 환경용 고정 키 (운영 환경에서는 절대 사용하지 말 것!)
    this.jwk = {
      kty: 'RSA',
      use: 'sig',
      kid: 'rsa-key-dev',
      n: '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtmUAmh9K8X1GYTAJwTDFb',
      e: 'AQAB',
      alg: 'RS256',
    };
  }
  @Get('jwks.json')
  @ApiOperation({
    summary: 'JSON Web Key Set',
    description: 'ID 토큰 검증에 필요한 공개키 정보를 제공합니다.',
  })
  @ApiResponse({
    status: 200,
    description: 'JWKS 정보',
  })
  getJwks() {
    return {
      keys: [this.jwk],
    };
  }
}
