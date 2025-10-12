import { Injectable, Inject } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import type { Cache } from 'cache-manager';
import * as crypto from 'crypto';
import { User } from '../../auth/user.entity';
import { Client } from '../client.entity';
import { Token } from '../token.entity';
import { JWT_CONSTANTS } from '../../constants/jwt.constants';
import { TOKEN_TYPES } from '../../constants/auth.constants';
import { StructuredLogger } from '../../logging/structured-logger.service';
import { JwtTokenService } from './jwt-token.service';
import { IdTokenService } from './id-token.service';

interface TokenCreateResponse {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
  scopes: string[];
  tokenType: string;
  idToken?: string;
}

interface ImplicitTokenResponse {
  accessToken?: string;
  idToken?: string;
  tokenType: string;
  expiresIn?: number;
}

@Injectable()
export class OAuth2TokenService {
  constructor(
    @InjectRepository(Token)
    private tokenRepository: Repository<Token>,
    private jwtService: JwtService,
    private configService: ConfigService,
    private structuredLogger: StructuredLogger,
    private jwtTokenService: JwtTokenService,
    private idTokenService: IdTokenService,
    @Inject(CACHE_MANAGER)
    private cacheManager: Cache,
  ) {}

  async createToken(
    user: User | null,
    client: Client,
    scopes: string[] = [],
    nonce?: string,
    authTime?: number,
  ): Promise<TokenCreateResponse> {
    return this.tokenRepository.manager.transaction(async (manager) => {
      if (this.isDebugMode()) {
        this.structuredLogger.debug(
          {
            message: 'createToken called',
            userId: user?.id,
            clientId: client?.clientId,
            scopes,
            hasOpenid: scopes.includes('openid'),
          },
          'OAuth2TokenService',
        );
      }

      // Generate initial access token (will be replaced with jti)
      const accessToken = this.generateAccessToken(user, client, scopes);

      const refreshToken = this.generateRefreshToken();

      const expiresAt = new Date();
      expiresAt.setHours(
        expiresAt.getHours() + this.getAccessTokenExpiryHours(),
      );

      const refreshExpiresAt = new Date();
      refreshExpiresAt.setDate(
        refreshExpiresAt.getDate() + this.getRefreshTokenExpiryDays(),
      );

      // Generate token family ID for rotation tracking
      const tokenFamily = crypto.randomUUID();

      const token = manager.create(Token, {
        accessToken,
        refreshToken,
        expiresAt,
        refreshExpiresAt,
        scopes,
        user: user || undefined,
        client,
        tokenType: TOKEN_TYPES.OAUTH2,
        tokenFamily,
        rotationGeneration: 1,
      });

      await manager.save(Token, token);

      // Regenerate access token with jti for revocation capability
      const finalAccessToken = this.generateAccessTokenWithJti(
        user,
        client,
        scopes,
        token.id,
      );

      // Update token with final access token
      token.accessToken = finalAccessToken;
      await manager.save(Token, token);

      const response: TokenCreateResponse = {
        accessToken: finalAccessToken,
        refreshToken,
        expiresIn: this.getAccessTokenExpirySeconds(),
        scopes: scopes || [],
        tokenType: JWT_CONSTANTS.TOKEN_TYPE,
      };

      // Generate ID token if openid scope is requested and user exists
      if (user && scopes.includes('openid')) {
        try {
          response.idToken = await this.generateIdToken(
            user,
            client,
            scopes,
            nonce,
            authTime,
          );
        } catch (error) {
          this.structuredLogger.logError(error as Error, 'OAuth2TokenService', {
            operation: 'generateIdToken',
            userId: user.id,
            clientId: client.clientId,
          });
          // ID 토큰 생성 실패해도 액세스 토큰은 유지
        }
      }

      return response;
    });
  }

  /**
   * Create tokens for Implicit Grant flow (OpenID Connect)
   * Implicit Grant에서는 토큰을 데이터베이스에 저장하지 않고 직접 생성하여 반환
   */
  async createImplicitTokens(
    user: User,
    client: Client,
    scopes: string[],
    nonce?: string,
  ): Promise<ImplicitTokenResponse> {
    const response: ImplicitTokenResponse = {
      tokenType: JWT_CONSTANTS.TOKEN_TYPE,
    };

    // 액세스 토큰 생성 (openid 스코프가 있는 경우)
    if (scopes.includes('openid')) {
      const accessToken = this.generateAccessToken(user, client, scopes);
      response.accessToken = accessToken;
      response.expiresIn = this.getAccessTokenExpirySeconds();

      // ID 토큰 생성
      const authTime = Math.floor(Date.now() / 1000);
      response.idToken = await this.generateIdToken(
        user,
        client,
        scopes,
        nonce,
        authTime,
      );
    } else {
      // openid 스코프가 없으면 액세스 토큰만 생성
      const accessToken = this.generateAccessToken(user, client, scopes);
      response.accessToken = accessToken;
      response.expiresIn = this.getAccessTokenExpirySeconds();
    }

    return response;
  }

  async refreshToken(
    refreshTokenValue: string,
    clientId: string,
  ): Promise<TokenCreateResponse | null> {
    // Use transaction to prevent race conditions
    return await this.tokenRepository.manager.transaction(async (manager) => {
      const token = await manager.findOne(Token, {
        where: { refreshToken: refreshTokenValue },
        relations: ['user', 'client'],
      });

      if (!token) {
        return null;
      }

      if (!token.client) {
        return null;
      }

      // Verify client matches
      if (token.client.clientId !== clientId) {
        return null;
      }

      // Check if refresh token is expired
      if (token.refreshExpiresAt && token.refreshExpiresAt < new Date()) {
        return null;
      }

      // Check if refresh token was already used
      if (token.isRefreshTokenUsed) {
        // Enhanced Security: revoke entire token family if refresh token reuse detected
        await this.revokeTokenFamily(token.tokenFamily, 'refresh_token_reuse');

        this.structuredLogger.logSecurity('refresh_token_reuse_detected', {
          tokenFamily: token.tokenFamily,
          generation: token.rotationGeneration,
          clientId: token.client.clientId,
          userId: token.user?.id,
          ip: null, // Should be passed from request context
        });

        return null;
      }

      // Mark refresh token as used
      token.isRefreshTokenUsed = true;
      await manager.save(token);

      // Generate new tokens
      const newAccessToken = this.generateAccessTokenWithJti(
        token.user || null,
        token.client,
        token.scopes || [],
        token.id,
      );
      const newRefreshToken = this.generateRefreshToken();

      const newExpiresAt = new Date();
      newExpiresAt.setHours(
        newExpiresAt.getHours() + this.getAccessTokenExpiryHours(),
      );

      const newRefreshExpiresAt = new Date();
      newRefreshExpiresAt.setDate(
        newRefreshExpiresAt.getDate() + this.getRefreshTokenExpiryDays(),
      );

      // Create new token with updated family generation
      const newToken = manager.create(Token, {
        accessToken: newAccessToken,
        refreshToken: newRefreshToken,
        expiresAt: newExpiresAt,
        refreshExpiresAt: newRefreshExpiresAt,
        scopes: token.scopes,
        user: token.user || undefined,
        client: token.client,
        tokenType: TOKEN_TYPES.OAUTH2,
        tokenFamily: token.tokenFamily,
        rotationGeneration: (token.rotationGeneration || 1) + 1,
        isRefreshTokenUsed: false,
      });

      await manager.save(newToken);

      return {
        accessToken: newAccessToken,
        refreshToken: newRefreshToken,
        expiresIn: this.getAccessTokenExpirySeconds(),
        scopes: token.scopes || [],
        tokenType: JWT_CONSTANTS.TOKEN_TYPE,
      };
    });
  }

  private generateAccessToken(
    user: User | null,
    client: Client,
    scopes: string[],
  ): string {
    const payload = {
      sub: user?.id?.toString() || client.clientId,
      client_id: client.clientId,
      scope: scopes.join(' '),
      token_type: 'Bearer',
    };

    return this.jwtService.sign(payload);
  }

  private generateAccessTokenWithJti(
    user: User | null,
    client: Client,
    scopes: string[],
    jti: number,
  ): string {
    const payload = {
      sub: user?.id?.toString() || client.clientId,
      client_id: client.clientId,
      scope: scopes.join(' '),
      token_type: 'Bearer',
      jti: jti.toString(),
    };

    return this.jwtService.sign(payload);
  }

  private generateRefreshToken(): string {
    return crypto.randomBytes(32).toString('hex');
  }

  private getAccessTokenExpiryHours(): number {
    return this.configService.get<number>('ACCESS_TOKEN_EXPIRY_HOURS') || 1;
  }

  private getRefreshTokenExpiryDays(): number {
    return this.configService.get<number>('REFRESH_TOKEN_EXPIRY_DAYS') || 30;
  }

  private getAccessTokenExpirySeconds(): number {
    return this.getAccessTokenExpiryHours() * 60 * 60;
  }

  private async generateIdToken(
    user: User,
    client: Client,
    scopes: string[] = [],
    nonce?: string,
    authTime?: number,
  ): Promise<string> {
    return this.idTokenService.generateIdToken(
      user,
      client,
      scopes,
      nonce,
      authTime,
    );
  }

  private async revokeAllUserTokens(userId: number): Promise<void> {
    await this.tokenRepository.update(
      { user: { id: userId } },
      {
        accessToken: 'REVOKED',
        isRefreshTokenUsed: true,
        revokedReason: 'user_tokens_revoked',
        revokedAt: new Date(),
      },
    );
  }

  /**
   * Revoke entire token family when refresh token reuse is detected
   */
  private async revokeTokenFamily(
    tokenFamily: string | undefined,
    reason: string,
  ): Promise<void> {
    if (!tokenFamily) return;

    // Get all tokens in family before revoking
    const tokensInFamily = await this.tokenRepository.find({
      where: { tokenFamily },
      select: ['id'],
    });

    await this.tokenRepository.update(
      { tokenFamily },
      {
        isRevoked: true,
        revokedAt: new Date(),
        revokedReason: reason,
        accessToken: 'REVOKED',
        isRefreshTokenUsed: true,
      },
    );

    // Remove all tokens from cache
    for (const token of tokensInFamily) {
      await this.cacheManager.del(`oauth2_token:${token.id}`);
    }

    this.structuredLogger.logSecurity('token_family_revoked', {
      tokenFamily,
      reason,
      revokedTokens: tokensInFamily.length,
    });
  }

  /**
   * Get all tokens in a family for debugging
   */
  async getTokenFamily(tokenFamily: string): Promise<Token[]> {
    return this.tokenRepository.find({
      where: { tokenFamily },
      relations: ['user', 'client'],
      order: { createdAt: 'ASC' },
    });
  }

  private isDebugMode(): boolean {
    return this.configService.get<string>('NODE_ENV') !== 'production';
  }
}
