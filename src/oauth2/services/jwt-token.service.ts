import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JWT_CONSTANTS } from '../../constants/jwt.constants';
import { CACHE_CONFIG } from '../../constants/cache.constants';
import { CacheManagerService } from '../../cache/cache-manager.service';
import { createPrivateKey, createPublicKey, KeyObject } from 'crypto';
import { readFileSync } from 'fs';
import { resolve } from 'path';
import * as jwt from 'jsonwebtoken';

@Injectable()
export class JwtTokenService {
  constructor(
    private configService: ConfigService,
    private cacheManagerService: CacheManagerService,
  ) {}

  /**
   * Get RSA private key from file or environment variable
   */
  private getRsaPrivateKey(): string {
    // Try file first
    const privateKeyFile = this.configService.get<string>(
      'RSA_PRIVATE_KEY_FILE',
    );
    if (privateKeyFile) {
      try {
        // eslint-disable-next-line security/detect-non-literal-fs-filename
        return readFileSync(resolve(privateKeyFile), 'utf8');
      } catch {
        throw new Error(
          `Failed to read RSA private key file: ${privateKeyFile}`,
        );
      }
    }

    // Fallback to environment variable
    const privateKeyPem = this.configService.get<string>('RSA_PRIVATE_KEY');
    if (!privateKeyPem) {
      throw new Error(
        'RSA private key not configured. Set RSA_PRIVATE_KEY_FILE or RSA_PRIVATE_KEY.',
      );
    }
    return privateKeyPem;
  }

  /**
   * Sign JWT with RSA private key
   */
  async signJwtWithRSA(payload: Record<string, unknown>): Promise<string> {
    const privateKeyPem = this.getRsaPrivateKey();

    if (privateKeyPem) {
      // Sign with RSA key
      const privateKey = createPrivateKey(privateKeyPem);

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
    privateKey: KeyObject;
    kid: string;
  }> {
    const cacheKey = 'dev_rsa_key';

    // Check cache first
    const cached = await this.cacheManagerService.getCacheValue<{
      privateKey: KeyObject;
      kid: string;
    }>(cacheKey);
    if (cached) {
      return cached;
    }

    // Fetch development RSA private key from environment variable
    const privateKeyPem = this.getRsaPrivateKey();

    if (!privateKeyPem) {
      throw new Error(
        'Development RSA private key not found. Please set RSA_PRIVATE_KEY_FILE or RSA_PRIVATE_KEY.',
      );
    }

    const kid = JWT_CONSTANTS.KEY_IDS.RSA_DEV;

    const keyPair = { privateKey: createPrivateKey(privateKeyPem), kid };

    // Cache the key pair for future use
    await this.cacheManagerService.setCacheValue(
      cacheKey,
      keyPair,
      CACHE_CONFIG.TTL.STATIC_DATA,
    ); // 1 hour cache

    return keyPair;
  }

  /**
   * Fetch RSA public key
   */
  getRsaPublicKey(): KeyObject {
    const privateKeyPem = this.getRsaPrivateKey();

    if (!privateKeyPem) {
      throw new Error('RSA private key not configured');
    }

    const privateKey = createPrivateKey(privateKeyPem);
    return createPublicKey(privateKey);
  }

  /**
   * Get RSA private key PEM string
   */
  getRsaPrivateKeyPem(): string {
    return this.getRsaPrivateKey();
  }
}
