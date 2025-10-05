import { Injectable, Inject } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import type { Cache } from 'cache-manager';
import * as jwt from 'jsonwebtoken';
import * as crypto from 'crypto';
import { JWT_CONSTANTS } from '../../constants/jwt.constants';

@Injectable()
export class JwtTokenService {
  constructor(
    private jwtService: JwtService,
    private configService: ConfigService,
    @Inject(CACHE_MANAGER)
    private cacheManager: Cache,
  ) {}

  /**
   * JWT 토큰을 RSA 키로 서명
   */
  async signJwtWithRSA(payload: Record<string, any>): Promise<string> {
    const privateKeyPem = this.configService.get<string>('RSA_PRIVATE_KEY');

    if (privateKeyPem) {
      // RSA 키를 사용하여 서명
      const privateKey = crypto.createPrivateKey(privateKeyPem);

      // JWKS와 동일한 kid 사용
      const kid = JWT_CONSTANTS.KEY_IDS.RSA_ENV;

      const options: jwt.SignOptions = {
        algorithm: JWT_CONSTANTS.ALGORITHMS.RS256,
        header: {
          kid,
          alg: JWT_CONSTANTS.ALGORITHMS.RS256,
        },
      };

      return jwt.sign(payload, privateKey, options);
    } else {
      // 개발 환경에서도 RSA 키 생성하여 사용 (OIDC 표준 준수)
      const { privateKey, kid } = await this.getOrCreateDevRsaKey();

      const options: jwt.SignOptions = {
        algorithm: JWT_CONSTANTS.ALGORITHMS.RS256,
        header: {
          kid,
          alg: JWT_CONSTANTS.ALGORITHMS.RS256,
        },
      };

      return jwt.sign(payload, privateKey, options);
    }
  }

  /**
   * 개발 환경용 RSA 키 생성 또는 캐시된 키 반환
   */
  private async getOrCreateDevRsaKey(): Promise<{
    privateKey: crypto.KeyObject;
    kid: string;
  }> {
    const cacheKey = 'dev_rsa_key';

    // 캐시에서 키 확인
    const cached = await this.cacheManager.get<{
      privateKey: crypto.KeyObject;
      kid: string;
    }>(cacheKey);
    if (cached) {
      return cached;
    }

    // 환경 변수에서 개발용 RSA 개인키 가져오기
    const privateKeyPem = this.configService.get<string>('RSA_PRIVATE_KEY');

    if (!privateKeyPem) {
      throw new Error(
        'Development RSA private key not found. Please set RSA_PRIVATE_KEY environment variable.',
      );
    }

    const kid = JWT_CONSTANTS.KEY_IDS.RSA_DEV;

    const keyPair = { privateKey: crypto.createPrivateKey(privateKeyPem), kid };

    // 캐시에 저장 (메모리에만 저장)
    await this.cacheManager.set(
      cacheKey,
      keyPair,
      JWT_CONSTANTS.TIME.ONE_HOUR_MILLISECONDS,
    ); // 1시간 캐시

    return keyPair;
  }

  /**
   * RSA 공개키 가져오기
   */
  getRsaPublicKey(): crypto.KeyObject {
    const privateKeyPem = this.configService.get<string>('RSA_PRIVATE_KEY');

    if (!privateKeyPem) {
      throw new Error('RSA private key not configured');
    }

    const privateKey = crypto.createPrivateKey(privateKeyPem);
    return crypto.createPublicKey(privateKey);
  }

  /**
   * 디버그 모드 확인
   */
  private isDebugMode(): boolean {
    return this.configService.get<string>('NODE_ENV') !== 'production';
  }
}
