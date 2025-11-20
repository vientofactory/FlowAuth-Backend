import { Controller, Get, Logger, UsePipes } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { JwtTokenService } from '../services/jwt-token.service';

// RFC 7517 JWK (JSON Web Key) Interface
interface JWK {
  kty: string; // Key Type (RSA, EC, oct, etc.)
  use?: string; // Public Key Use (sig, enc)
  key_ops?: string[]; // Key Operations
  alg?: string; // Algorithm
  kid?: string; // Key ID
  x5u?: string; // X.509 URL
  x5c?: string[]; // X.509 Certificate Chain
  x5t?: string; // X.509 Certificate SHA-1 Thumbprint
  'x5t#S256'?: string; // X.509 Certificate SHA-256 Thumbprint
  // RSA Key Parameters
  n?: string; // Modulus
  e?: string; // Exponent
  d?: string; // Private Exponent
  p?: string; // First Prime Factor
  q?: string; // Second Prime Factor
  dp?: string; // First Factor CRT Exponent
  dq?: string; // Second Factor CRT Exponent
  qi?: string; // First CRT Coefficient
  // EC Key Parameters
  crv?: string; // Curve
  x?: string; // X Coordinate
  y?: string; // Y Coordinate
}

@ApiTags('OpenID Connect')
@Controller('.well-known')
export class JwksController {
  private readonly logger = new Logger(JwksController.name);
  private jwk: JWK;

  constructor(private readonly jwtTokenService: JwtTokenService) {
    // 애플리케이션 시작 시 JWK 생성 또는 환경 변수에서 로드
    this.initializeJWK();
  }

  private initializeJWK(): void {
    try {
      // Get RSA public key from JWT service
      const publicKey = this.jwtTokenService.getRsaPublicKey();
      const jwk = publicKey.export({ format: 'jwk' });

      this.jwk = {
        kty: jwk.kty!,
        use: 'sig',
        kid: 'rsa-key-env',
        n: jwk.n!,
        e: jwk.e!,
        alg: 'RS256',
      };
    } catch (error) {
      this.logger.error('Failed to initialize JWK from RSA key', error);
      throw new Error(
        'RSA key configuration error. ' +
          'Set RSA_PRIVATE_KEY_FILE or RSA_PRIVATE_KEY environment variable. ' +
          'Run ./generate_rsa_keys.sh to generate a key pair.',
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
