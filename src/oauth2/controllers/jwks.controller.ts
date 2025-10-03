import { Controller, Get } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';

@ApiTags('OpenID Connect JWKS')
@Controller('.well-known')
export class JwksController {
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
    // 실제 운영 환경에서는 환경 변수나 키 관리 시스템에서 RSA 공개키를 가져와야 함
    // 현재는 예시 키를 반환 (개발용)
    return {
      keys: [
        {
          kty: 'RSA',
          use: 'sig',
          kid: 'rsa-key-1',
          n: '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtmUAmh9K8X1GYTAJwTDFb',
          e: 'AQAB',
          alg: 'RS256',
        },
      ],
    };
  }
}
