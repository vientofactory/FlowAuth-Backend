import { Injectable, Inject } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import type { Cache } from 'cache-manager';
import * as crypto from 'crypto';
import { User } from '../../auth/user.entity';
import { Client } from '../client.entity';
import { JWT_CONSTANTS } from '../../constants/jwt.constants';
import { CACHE_CONFIG } from '../../constants/cache.constants';
import { StructuredLogger } from '../../logging/structured-logger.service';
import { JwtTokenService } from './jwt-token.service';

export interface IdTokenPayload {
  iss: string;
  sub: string;
  aud: string;
  exp: number;
  iat: number;
  auth_time: number;
  nonce?: string;
  // profile scope claims
  name?: string;
  preferred_username?: string;
  given_name?: string;
  family_name?: string;
  picture?: string;
  updated_at?: number;
  // email scope claims
  email?: string;
  email_verified?: boolean;
  // phone scope claims
  phone_number?: string;
  phone_number_verified?: boolean;
  // address scope claims
  address?: AddressClaim;
}

export interface AddressClaim {
  formatted?: string;
  street_address?: string;
  locality?: string;
  region?: string;
  postal_code?: string;
  country?: string;
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
    scopes: string[] = [],
    nonce?: string,
    authTime?: number,
  ): Promise<string> {
    const baseUrl =
      this.configService.get<string>('BACKEND_URL') ?? 'http://localhost:3000';

    // Define standard ID token claims
    const payload: IdTokenPayload = {
      iss: baseUrl,
      sub: user.id.toString(),
      aud: client.clientId,
      exp: Math.floor(Date.now() / 1000) + JWT_CONSTANTS.TIME.ONE_HOUR_SECONDS,
      iat: Math.floor(Date.now() / 1000),
      auth_time: authTime ?? Math.floor(Date.now() / 1000),
    };

    // Add nonce if present (OpenID Connect requirement)
    if (nonce) {
      payload.nonce = nonce;
    }

    // Add claims based on scopes
    this.addClaimsBasedOnScopes(payload, user, scopes);

    return await this.jwtTokenService.signJwtWithRSA(
      payload as unknown as Record<string, unknown>,
    );
  }

  /**
   * Add claims to ID token payload based on granted scopes
   */
  private addClaimsBasedOnScopes(
    payload: IdTokenPayload,
    user: User,
    scopes: string[],
  ) {
    // profile scope: User profile information
    if (scopes.includes('profile')) {
      payload.name = user.username || '';
      payload.preferred_username = user.username || '';
      payload.given_name = user.firstName ?? '';
      payload.family_name = user.lastName ?? '';
      payload.picture = user.avatar ?? '';
      payload.updated_at = user.updatedAt
        ? Math.floor(user.updatedAt.getTime() / 1000)
        : undefined;
    }

    // email scope: Email information
    if (scopes.includes('email')) {
      payload.email = user.email || '';
      payload.email_verified = !!user.isEmailVerified;
    }
  }

  /**
   * Get RSA public key from JWT service
   */
  private async getRsaPublicKey(kid: string): Promise<crypto.KeyObject> {
    try {
      // Check public key in cache first
      const cacheKey = `rsa_public_key:${kid}`;
      let publicKey: crypto.KeyObject | undefined =
        await this.cacheManager.get(cacheKey);

      if (!publicKey) {
        // Get RSA public key from JWT service
        publicKey = this.jwtTokenService.getRsaPublicKey();

        // Cache the public key to avoid repeated internal calls
        await this.cacheManager.set(
          cacheKey,
          publicKey,
          CACHE_CONFIG.TTL.STATIC_DATA,
        );
      }

      return publicKey;
    } catch (error) {
      this.structuredLogger.error(
        {
          message: 'Failed to get RSA public key internally',
          kid,
          error: error instanceof Error ? error.message : 'Unknown error',
        },
        'IdTokenService',
      );
      throw new Error('Failed to get RSA public key');
    }
  }

  /**
   * Validate ID token signature and claims
   */
  async validateIdToken(
    idToken: string,
    expectedClientId: string,
    expectedNonce?: string,
  ): Promise<IdTokenPayload> {
    try {
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

      // Development environment token - skip RSA validation
      if (header.alg === JWT_CONSTANTS.ALGORITHMS.HS256) {
        return payload;
      }

      // RSA signature verification
      if (header.alg !== JWT_CONSTANTS.ALGORITHMS.RS256) {
        throw new Error('Unsupported algorithm');
      }

      const kid = header.kid;
      if (!kid) {
        throw new Error('Key ID (kid) not found in token header');
      }

      // Fetch public key
      const publicKey = await this.getRsaPublicKey(kid);

      // Verify signature
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

      // Validate standard claims
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
