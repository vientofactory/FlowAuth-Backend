import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { TokenService } from '../token.service';
import { Token } from '../token.entity';
import { Client } from '../client.entity';
import { TOKEN_INTROSPECTION_CONSTANTS } from '../../constants/jwt.constants';

export interface TokenIntrospectionResult {
  active: boolean;
  client_id?: string;
  exp?: number;
  iat?: number;
  sub?: string;
  scope?: string | null;
  token_type?: string;
  username?: string | null;
  email?: string | null;
  email_verified?: boolean;
}

interface AccessTokenPayload {
  client_id?: string;
  exp?: number;
  iat?: number;
  sub?: string;
  scopes?: string[];
  [key: string]: unknown;
}

@Injectable()
export class TokenIntrospectionService {
  private readonly logger = new Logger(TokenIntrospectionService.name);

  constructor(
    private readonly tokenService: TokenService,
    @InjectRepository(Token)
    private readonly tokenRepository: Repository<Token>,
    @InjectRepository(Client)
    private readonly clientRepository: Repository<Client>,
  ) {}

  /**
   * Identify token type based on format and hint
   */
  determineTokenType(token: string, hint?: string): string {
    // If a hint is provided, use it first
    if (hint) {
      return hint;
    }

    // If the token is in JWT format, determine type from headers/payload
    if (token.split('.').length === 3) {
      try {
        const payload = JSON.parse(
          Buffer.from(token.split('.')[1], 'base64url').toString(),
        ) as { nonce?: string; scopes?: string[]; scope?: string };

        if (payload.nonce !== undefined) {
          return 'id_token';
        }

        if (payload.scopes || payload.scope) {
          return 'access_token';
        }
      } catch {
        // If parsing fails, default to access_token
      }
    }

    // Default to access_token
    return 'access_token';
  }

  /**
   * ID Token introspection
   */
  async introspectIdToken(
    token: string,
    expectedClientId?: string,
  ): Promise<TokenIntrospectionResult> {
    try {
      // Check or extract client ID
      let clientId = expectedClientId;
      if (!clientId) {
        // Extract audience from token to determine client ID
        const payload = JSON.parse(
          Buffer.from(token.split('.')[1], 'base64url').toString(),
        ) as { aud?: string };
        clientId = payload.aud;
      }

      if (!clientId) {
        throw new Error('Client ID not found in token or request');
      }

      // Check if client exists
      const client = await this.clientRepository.findOne({
        where: { clientId },
      });
      if (!client) {
        throw new Error('Invalid client');
      }

      // ID Token validation (RSA signature + claims validation)
      const payload = await this.tokenService.validateIdToken(
        token,
        clientId,
        undefined,
      );

      // Safe claim key mapping
      const CLAIM_KEYS = {
        USERNAME: TOKEN_INTROSPECTION_CONSTANTS.CLAIMS.USERNAME,
        EMAIL_VERIFIED: TOKEN_INTROSPECTION_CONSTANTS.CLAIMS.EMAIL_VERIFIED,
      } as const;

      // Type-safe claim extraction using Map-based safe access
      const claimMap = new Map(Object.entries(payload));

      const username = claimMap.has(CLAIM_KEYS.USERNAME)
        ? (claimMap.get(CLAIM_KEYS.USERNAME) as string)
        : payload.name;

      const emailVerified = claimMap.has(CLAIM_KEYS.EMAIL_VERIFIED)
        ? (claimMap.get(CLAIM_KEYS.EMAIL_VERIFIED) as boolean)
        : payload.email_verified;

      return {
        active: true,
        client_id: payload.aud,
        exp: payload.exp,
        iat: payload.iat,
        sub: payload.sub,
        token_type: TOKEN_INTROSPECTION_CONSTANTS.TOKEN_TYPES.ID_TOKEN,
        username: username ?? null,
        email: payload.email ?? null,
        email_verified: emailVerified,
      };
    } catch (error) {
      this.logger.warn(
        {
          message: 'ID token introspection failed',
          error: error instanceof Error ? error.message : 'Unknown error',
        },
        'TokenIntrospectionService',
      );
      return { active: TOKEN_INTROSPECTION_CONSTANTS.TOKEN_STATUS.INACTIVE };
    }
  }

  /**
   * Access Token introspection
   */
  async introspectAccessToken(
    token: string,
  ): Promise<TokenIntrospectionResult> {
    try {
      // Access Token validation (signature + claims)
      const rawPayload = await this.tokenService.validateToken(token);

      if (!rawPayload) {
        return { active: TOKEN_INTROSPECTION_CONSTANTS.TOKEN_STATUS.INACTIVE };
      }

      // Type-safe payload conversion (safe type conversion through unknown)
      const payload = rawPayload as unknown as AccessTokenPayload;

      // Check if client exists
      const clientId = payload.client_id ?? '';
      const client = await this.clientRepository.findOne({
        where: { clientId },
      });
      if (!client) {
        return { active: TOKEN_INTROSPECTION_CONSTANTS.TOKEN_STATUS.INACTIVE };
      }

      return {
        active: true,
        client_id: payload.client_id,
        exp: payload.exp,
        iat: payload.iat,
        sub: payload.sub,
        scope: Array.isArray(payload.scopes) ? payload.scopes.join(' ') : null,
        token_type: TOKEN_INTROSPECTION_CONSTANTS.TOKEN_TYPES.ACCESS_TOKEN,
        username: payload.sub,
      };
    } catch (error) {
      this.logger.warn(
        {
          message: 'Access token introspection failed',
          error: error instanceof Error ? error.message : 'Unknown error',
        },
        'TokenIntrospectionService',
      );
      return { active: TOKEN_INTROSPECTION_CONSTANTS.TOKEN_STATUS.INACTIVE };
    }
  }

  /**
   * Refresh Token introspection
   */
  async introspectRefreshToken(
    token: string,
  ): Promise<TokenIntrospectionResult> {
    try {
      // Find the refresh token in the database
      const tokenEntity = await this.tokenRepository.findOne({
        where: { refreshToken: token },
        relations: ['user', 'client'],
      });

      if (!tokenEntity || tokenEntity.isRevoked) {
        return { active: TOKEN_INTROSPECTION_CONSTANTS.TOKEN_STATUS.INACTIVE };
      }

      // Check if refresh token is expired
      const now = new Date();
      if (!tokenEntity.refreshExpiresAt || tokenEntity.refreshExpiresAt < now) {
        return { active: TOKEN_INTROSPECTION_CONSTANTS.TOKEN_STATUS.INACTIVE };
      }

      // Check if client exists
      if (!tokenEntity.client) {
        return { active: TOKEN_INTROSPECTION_CONSTANTS.TOKEN_STATUS.INACTIVE };
      }

      const client = await this.clientRepository.findOne({
        where: {
          clientId: tokenEntity.client.clientId,
        },
      });
      if (!client) {
        return { active: TOKEN_INTROSPECTION_CONSTANTS.TOKEN_STATUS.INACTIVE };
      }

      return {
        active: true,
        client_id: tokenEntity.client.clientId,
        exp: Math.floor(tokenEntity.refreshExpiresAt.getTime() / 1000),
        iat: Math.floor(tokenEntity.createdAt.getTime() / 1000),
        sub: tokenEntity.user?.id.toString(),
        scope: tokenEntity.scopes ? tokenEntity.scopes.join(' ') : null,
        token_type: TOKEN_INTROSPECTION_CONSTANTS.TOKEN_TYPES.REFRESH_TOKEN,
        username: tokenEntity.user?.username ?? null,
      };
    } catch (error) {
      this.logger.warn(
        {
          message: 'Refresh token introspection failed',
          error: error instanceof Error ? error.message : 'Unknown error',
        },
        'TokenIntrospectionService',
      );
      return { active: TOKEN_INTROSPECTION_CONSTANTS.TOKEN_STATUS.INACTIVE };
    }
  }

  /**
   * Token introspection main method
   */
  async introspectToken(
    token: string,
    tokenTypeHint?: string,
  ): Promise<TokenIntrospectionResult> {
    const tokenType = this.determineTokenType(token, tokenTypeHint);

    switch (tokenType) {
      case 'id_token':
        return await this.introspectIdToken(token);
      case 'access_token':
        return await this.introspectAccessToken(token);
      case 'refresh_token':
        return await this.introspectRefreshToken(token);
      default:
        return { active: TOKEN_INTROSPECTION_CONSTANTS.TOKEN_STATUS.INACTIVE };
    }
  }
}
