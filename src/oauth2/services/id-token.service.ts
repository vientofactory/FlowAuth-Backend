import { Injectable, Inject } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import type { Cache } from 'cache-manager';
import * as crypto from 'crypto';
import axios from 'axios';
import { User } from '../../auth/user.entity';
import { Client } from '../client.entity';
import { JWT_CONSTANTS, CACHE_CONSTANTS } from '../../constants/jwt.constants';
import { StructuredLogger } from '../../logging/structured-logger.service';
import { JwtTokenService } from './jwt-token.service';

interface JWKSKey {
  kty: string;
  kid: string;
  n: string;
  e: string;
  alg: string;
}

interface JWKSResponse {
  keys: JWKSKey[];
}

interface IdTokenPayload {
  iss: string;
  sub: string;
  aud: string;
  exp: number;
  iat: number;
  auth_time: number;
  nonce?: string;
  email: string;
  email_verified: boolean;
  name: string;
  preferred_username: string;
}

@Injectable()
export class IdTokenService {
  constructor(
    private configService: ConfigService,
    private structuredLogger: StructuredLogger,
    private jwtTokenService: JwtTokenService,
    @Inject(CACHE_MANAGER)
    private cacheManager: Cache,
  ) {}

  async generateIdToken(
    user: User,
    client: Client,
    nonce?: string,
    authTime?: number,
  ): Promise<string> {
    const baseUrl =
      this.configService.get<string>('BACKEND_URL') || 'http://localhost:3000';

    const payload = {
      iss: baseUrl,
      sub: user.id.toString(),
      aud: client.clientId,
      exp: Math.floor(Date.now() / 1000) + JWT_CONSTANTS.TIME.ONE_HOUR_SECONDS, // 1시간
      iat: Math.floor(Date.now() / 1000),
      auth_time: authTime || Math.floor(Date.now() / 1000),
      nonce: nonce,
      email: user.email || '',
      email_verified: !!user.isEmailVerified,
      name: user.username || '',
      preferred_username: user.username || '',
    };

    return await this.jwtTokenService.signJwtWithRSA(payload);
  }

  /**
   * JWKS에서 RSA 공개키 가져오기
   */
  private async getRsaPublicKey(kid: string): Promise<crypto.KeyObject> {
    const baseUrl =
      this.configService.get<string>('BACKEND_URL') || 'http://localhost:3000';
    const jwksUrl = `${baseUrl}${JWT_CONSTANTS.JWKS_PATH}`;

    try {
      // 캐시에서 JWKS 확인
      const cacheKey = `jwks:${jwksUrl}`;
      let jwks: JWKSResponse | undefined =
        await this.cacheManager.get(cacheKey);

      if (!jwks) {
        // HTTP 요청으로 JWKS 가져오기
        const response = await axios.get(jwksUrl);
        jwks = response.data as JWKSResponse;
        // 1시간 캐시
        await this.cacheManager.set(cacheKey, jwks, CACHE_CONSTANTS.JWKS_TTL);
      }

      const key = jwks.keys.find((k) => k.kid === kid);
      if (!key) {
        throw new Error(`Key with kid '${kid}' not found in JWKS`);
      }

      // JWK를 직접 사용하여 공개키 생성
      const publicKey = crypto.createPublicKey({
        key: {
          kty: key.kty,
          n: key.n,
          e: key.e,
        },
        format: 'jwk',
      });

      return publicKey;
    } catch (error) {
      this.structuredLogger.error(
        {
          message: 'Failed to fetch RSA public key',
          kid,
          error: error instanceof Error ? error.message : 'Unknown error',
        },
        'IdTokenService',
      );
      throw new Error('Failed to fetch RSA public key');
    }
  }

  /**
   * ID 토큰 검증 (RSA 서명 + 클레임 검증)
   */
  async validateIdToken(
    idToken: string,
    expectedClientId: string,
    expectedNonce?: string,
  ): Promise<IdTokenPayload> {
    try {
      // JWT 파싱
      const parts = idToken.split('.');
      if (parts.length !== 3) {
        throw new Error('Invalid JWT format');
      }

      const header = JSON.parse(
        Buffer.from(parts[0], 'base64url').toString(),
      ) as { alg: string; kid?: string };
      const payload = JSON.parse(
        Buffer.from(parts[1], 'base64url').toString(),
      ) as IdTokenPayload;
      const signature = parts[2];

      // 개발 환경 토큰은 검증 건너뛰기
      if (header.alg === JWT_CONSTANTS.ALGORITHMS.HS256) {
        this.structuredLogger.debug(
          {
            message:
              'Development environment token detected, skipping RSA validation',
          },
          'IdTokenService',
        );
        return payload;
      }

      // RSA 서명 검증
      if (header.alg !== JWT_CONSTANTS.ALGORITHMS.RS256) {
        throw new Error('Unsupported algorithm');
      }

      const kid = header.kid;
      if (!kid) {
        throw new Error('Key ID (kid) not found in token header');
      }

      // 공개키 가져오기
      const publicKey = await this.getRsaPublicKey(kid);

      // 서명 검증
      const data = `${parts[0]}.${parts[1]}`;
      const isValid = crypto.verify(
        'RSA-SHA256',
        Buffer.from(data),
        publicKey,
        Buffer.from(signature, 'base64url'),
      );

      if (!isValid) {
        throw new Error('Invalid token signature');
      }

      // 클레임 검증
      const now = Math.floor(Date.now() / 1000);

      if (payload.exp < now) {
        throw new Error('Token has expired');
      }

      if (payload.aud !== expectedClientId) {
        throw new Error('Invalid audience');
      }

      if (expectedNonce && payload.nonce !== expectedNonce) {
        throw new Error('Invalid nonce');
      }

      return payload;
    } catch (error) {
      this.structuredLogger.error(
        {
          message: 'ID token validation failed',
          error: error instanceof Error ? error.message : 'Unknown error',
        },
        'IdTokenService',
      );
      throw error;
    }
  }
}
