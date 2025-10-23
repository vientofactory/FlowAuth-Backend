import { Injectable, Inject } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import type { Cache } from 'cache-manager';
import * as jwt from 'jsonwebtoken';
import * as crypto from 'crypto';
import { JWT_CONSTANTS } from '../../constants/jwt.constants';

@Injectable()
export class JwtTokenService {
  constructor(
    private configService: ConfigService,
    @Inject(CACHE_MANAGER)
    private cacheManager: Cache,
  ) {}

  /**
   * Sign JWT with RSA private key
   */
  async signJwtWithRSA(payload: Record<string, unknown>): Promise<string> {
    const privateKeyPem = this.configService.get<string>('RSA_PRIVATE_KEY');

    if (privateKeyPem) {
      // Sign with RSA key
      const privateKey = crypto.createPrivateKey(privateKeyPem);

      // Use the same kid as JWKS
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
      // Development mode: use cached or new RSA key
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
   * Get or create development RSA key
   */
  private async getOrCreateDevRsaKey(): Promise<{
    privateKey: crypto.KeyObject;
    kid: string;
  }> {
    const cacheKey = 'dev_rsa_key';

    // Check cache first
    const cached = await this.cacheManager.get<{
      privateKey: crypto.KeyObject;
      kid: string;
    }>(cacheKey);
    if (cached) {
      return cached;
    }

    // Fetch development RSA private key from environment variable
    const privateKeyPem = this.configService.get<string>('RSA_PRIVATE_KEY');

    if (!privateKeyPem) {
      throw new Error(
        'Development RSA private key not found. Please set RSA_PRIVATE_KEY environment variable.',
      );
    }

    const kid = JWT_CONSTANTS.KEY_IDS.RSA_DEV;

    const keyPair = { privateKey: crypto.createPrivateKey(privateKeyPem), kid };

    // Cache the key pair for future use
    await this.cacheManager.set(
      cacheKey,
      keyPair,
      JWT_CONSTANTS.TIME.ONE_HOUR_MILLISECONDS,
    ); // 1 hour cache

    return keyPair;
  }

  /**
   * Fetch RSA public key
   */
  getRsaPublicKey(): crypto.KeyObject {
    const privateKeyPem = this.configService.get<string>('RSA_PRIVATE_KEY');

    if (!privateKeyPem) {
      throw new Error('RSA private key not configured');
    }

    const privateKey = crypto.createPrivateKey(privateKeyPem);
    return crypto.createPublicKey(privateKey);
  }
}
