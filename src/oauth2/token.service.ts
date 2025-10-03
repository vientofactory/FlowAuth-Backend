import { Injectable, UnauthorizedException, Inject } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, LessThan } from 'typeorm';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import type { Cache } from 'cache-manager';
import * as jwt from 'jsonwebtoken';
import { AppConfigService } from '../config/app-config.service';
import { Token } from './token.entity';
import { User } from '../auth/user.entity';
import { Client } from './client.entity';
import { OAuth2JwtPayload } from '../types/oauth2.types';
import { StructuredLogger } from '../logging/structured-logger.service';
import { TOKEN_TYPES, JWT_TOKEN_EXPIRY } from '../constants/auth.constants';
import * as crypto from 'crypto';

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
export class TokenService {
  constructor(
    @InjectRepository(Token)
    private readonly tokenRepository: Repository<Token>,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
    @Inject(CACHE_MANAGER)
    private readonly cacheManager: Cache,
    private readonly appConfigService: AppConfigService,
    private readonly structuredLogger: StructuredLogger,
  ) {}

  private getAccessTokenExpiryHours(): number {
    return JWT_TOKEN_EXPIRY.OAUTH2_HOURS;
  }

  private getRefreshTokenExpiryDays(): number {
    return this.appConfigService.refreshTokenExpiryDays;
  }

  private getAccessTokenExpirySeconds(): number {
    return this.getAccessTokenExpiryHours() * 3600;
  }

  private getJwtSecret(): string {
    return (
      this.configService.get<string>('JWT_SECRET') || 'fallback-secret-key'
    );
  }

  private signJwt(payload: Record<string, any>): string {
    const secret = this.getJwtSecret();
    return jwt.sign(payload, secret);
  }

  private isDebugMode(): boolean {
    return this.configService.get<string>('NODE_ENV') !== 'production';
  }

  async createToken(
    user: User | null,
    client: Client,
    scopes: string[] = [],
    nonce?: string,
    authTime?: number,
  ): Promise<TokenCreateResponse> {
    if (this.isDebugMode()) {
      this.structuredLogger.debug(
        {
          message: 'createToken called',
          userId: user?.id,
          clientId: client?.clientId,
          scopes,
          hasOpenid: scopes.includes('openid'),
        },
        'TokenService',
      );
    }

    // Generate initial access token (will be replaced with jti)
    const accessToken = this.generateAccessToken(user, client, scopes);

    const refreshToken = this.generateRefreshToken();

    const expiresAt = new Date();
    expiresAt.setHours(expiresAt.getHours() + this.getAccessTokenExpiryHours());

    const refreshExpiresAt = new Date();
    refreshExpiresAt.setDate(
      refreshExpiresAt.getDate() + this.getRefreshTokenExpiryDays(),
    );

    const token = this.tokenRepository.create({
      accessToken,
      refreshToken,
      expiresAt,
      refreshExpiresAt,
      scopes,
      user: user || undefined,
      client,
      tokenType: TOKEN_TYPES.OAUTH2,
    });

    try {
      await this.tokenRepository.save(token);

      // Regenerate access token with jti for revocation capability
      const finalAccessToken = this.generateAccessTokenWithJti(
        user,
        client,
        scopes,
        token.id,
      );

      // Update token with final access token
      token.accessToken = finalAccessToken;
      await this.tokenRepository.save(token);

      const response: TokenCreateResponse = {
        accessToken: finalAccessToken,
        refreshToken,
        expiresIn: this.getAccessTokenExpirySeconds(),
        scopes: scopes || [],
        tokenType: 'Bearer',
      };

      // Generate ID token if openid scope is requested and user exists
      if (user && scopes.includes('openid')) {
        response.idToken = this.generateIdToken(user, client, nonce, authTime);
      }

      return response;
    } catch (error) {
      this.structuredLogger.logError(error as Error, 'TokenService', {
        operation: 'saveToken',
      });
      throw error;
    }
  }

  /**
   * Create tokens for Implicit Grant flow (OpenID Connect)
   * Implicit Grant에서는 토큰을 데이터베이스에 저장하지 않고 직접 생성하여 반환
   */
  createImplicitTokens(
    user: User,
    client: Client,
    scopes: string[],
    nonce?: string,
  ): ImplicitTokenResponse {
    const response: ImplicitTokenResponse = {
      tokenType: 'Bearer',
    };

    // 액세스 토큰 생성 (openid 스코프가 있는 경우)
    if (scopes.includes('openid')) {
      const accessToken = this.generateAccessToken(user, client, scopes);
      response.accessToken = accessToken;
      response.expiresIn = this.getAccessTokenExpirySeconds();

      // ID 토큰 생성
      const authTime = Math.floor(Date.now() / 1000);
      response.idToken = this.generateIdToken(user, client, nonce, authTime);
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
      // Find token by refresh token with pessimistic locking
      const token = await manager.findOne(Token, {
        where: { refreshToken: refreshTokenValue },
        relations: ['user', 'client'],
        lock: { mode: 'pessimistic_write' },
      });

      if (!token) {
        throw new UnauthorizedException('Invalid refresh token');
      }

      // Verify that the refresh token belongs to the requesting client
      // Only check client for OAuth2 tokens (tokens with client)
      if (token.client && token.client.clientId !== clientId) {
        throw new UnauthorizedException(
          'Refresh token does not belong to this client',
        );
      }

      // Check if refresh token is expired
      if (token.refreshExpiresAt && new Date() > token.refreshExpiresAt) {
        // Remove expired token
        await manager.remove(Token, token);
        throw new UnauthorizedException('Refresh token expired');
      }

      // Check if refresh token has been used (prevent reuse)
      if (token.isRefreshTokenUsed) {
        // Remove compromised token
        await manager.remove(Token, token);
        throw new UnauthorizedException('Refresh token has already been used');
      }

      // Mark refresh token as used to prevent reuse
      token.isRefreshTokenUsed = true;
      await manager.save(Token, token);

      // Generate new access token
      const newAccessToken = this.generateAccessToken(
        token.user || null,
        token.client || null,
        token.scopes || [],
      );
      const newRefreshToken = this.generateRefreshToken();

      const expiresAt = new Date();
      expiresAt.setHours(
        expiresAt.getHours() + this.getAccessTokenExpiryHours(),
      );

      const refreshExpiresAt = new Date();
      refreshExpiresAt.setDate(
        refreshExpiresAt.getDate() + this.getRefreshTokenExpiryDays(),
      );

      // Create new token record (rotation)
      const newToken = manager.create(Token, {
        accessToken: newAccessToken,
        refreshToken: newRefreshToken,
        expiresAt,
        refreshExpiresAt,
        scopes: token.scopes,
        user: token.user,
        client: token.client,
        isRefreshTokenUsed: false,
      });

      await manager.save(Token, newToken);

      // Regenerate access token with jti for the new token
      const finalAccessToken = this.generateAccessTokenWithJti(
        token.user || null,
        token.client || null,
        token.scopes || [],
        newToken.id,
      );

      // Update token with final access token
      newToken.accessToken = finalAccessToken;
      await manager.save(Token, newToken);

      // Remove old token after creating new one
      await manager.remove(Token, token);

      return {
        accessToken: finalAccessToken,
        refreshToken: newRefreshToken,
        expiresIn: this.getAccessTokenExpirySeconds(),
        scopes: token.scopes || [],
        tokenType: 'Bearer',
      };
    });
  }

  async validateToken(accessToken: string): Promise<OAuth2JwtPayload | null> {
    try {
      // Check cache first for performance
      const cachedToken = await this.cacheManager.get<OAuth2JwtPayload>(
        `token:${accessToken}`,
      );
      if (cachedToken) {
        return cachedToken;
      }

      // Verify JWT token
      const decoded = this.jwtService.verify<OAuth2JwtPayload>(accessToken);

      // Check if token exists in database and is not revoked
      const token = await this.tokenRepository.findOne({
        where: { accessToken },
        relations: ['user', 'client'],
      });

      if (!token) {
        return null;
      }

      // Check if token is expired
      if (token.expiresAt && new Date() > token.expiresAt) {
        // Remove expired token
        await this.tokenRepository.remove(token);
        return null;
      }

      // 유효한 토큰을 캐시에 저장 (5분)
      await this.cacheManager.set(`token:${accessToken}`, decoded, 300000);

      return decoded;
    } catch {
      return null;
    }
  }

  async revokeToken(accessToken: string): Promise<void> {
    const token = await this.tokenRepository.findOne({
      where: { accessToken },
    });

    if (token) {
      token.isRevoked = true;
      token.revokedAt = new Date();
      await this.tokenRepository.save(token);
    }
  }

  async revokeRefreshToken(refreshToken: string): Promise<void> {
    const token = await this.tokenRepository.findOne({
      where: { refreshToken },
    });

    if (token) {
      token.isRevoked = true;
      token.revokedAt = new Date();
      await this.tokenRepository.save(token);
    }
  }

  async revokeAllUserTokens(userId: number): Promise<void> {
    const tokens = await this.tokenRepository.find({
      where: { user: { id: userId }, isRevoked: false },
    });

    const now = new Date();
    for (const token of tokens) {
      token.isRevoked = true;
      token.revokedAt = now;
    }

    await this.tokenRepository.save(tokens);
  }

  async revokeAllClientTokens(clientId: string): Promise<void> {
    const tokens = await this.tokenRepository.find({
      where: { client: { clientId }, isRevoked: false },
    });

    const now = new Date();
    for (const token of tokens) {
      token.isRevoked = true;
      token.revokedAt = now;
    }

    await this.tokenRepository.save(tokens);
  }

  async cleanupExpiredTokens(): Promise<number> {
    const now = new Date();
    const result = await this.tokenRepository.delete({
      expiresAt: LessThan(now),
    });
    return result.affected || 0;
  }

  private generateAccessToken(
    user: User | null,
    client: Client | null,
    scopes: string[],
  ): string {
    if (this.isDebugMode()) {
      this.structuredLogger.debug(
        {
          message: 'generateAccessToken called',
          userId: user?.id,
          clientId: client?.clientId,
          scopes,
        },
        'TokenService',
      );
    }

    const payload: OAuth2JwtPayload = {
      sub: user?.id?.toString() || null,
      client_id: client?.clientId || null,
      scopes,
      token_type: 'Bearer',
      exp:
        Math.floor(Date.now() / 1000) + this.getAccessTokenExpiryHours() * 3600,
      iat: Math.floor(Date.now() / 1000),
    };

    if (this.isDebugMode()) {
      this.structuredLogger.debug(
        {
          message: 'Access token payload',
          payloadKeys: Object.keys(payload),
          hasExp: 'exp' in payload,
          hasIat: 'iat' in payload,
          exp: payload.exp,
          iat: payload.iat,
        },
        'TokenService',
      );
    }

    const token = this.signJwt(payload);

    if (this.isDebugMode()) {
      this.structuredLogger.debug(
        {
          message: 'Access token generated',
          tokenLength: token.length,
          tokenStart: token.substring(0, 50) + '...',
        },
        'TokenService',
      );
    }

    return token;
  }

  private generateAccessTokenWithJti(
    user: User | null,
    client: Client | null,
    scopes: string[],
    tokenId: number,
  ): string {
    if (this.isDebugMode()) {
      this.structuredLogger.debug(
        {
          message: 'generateAccessTokenWithJti called',
          userId: user?.id,
          clientId: client?.clientId,
          scopes,
          tokenId,
        },
        'TokenService',
      );
    }

    const payload: OAuth2JwtPayload = {
      sub: user?.id?.toString() || null,
      client_id: client?.clientId || null,
      scopes,
      token_type: 'Bearer',
      jti: tokenId.toString(),
      exp:
        Math.floor(Date.now() / 1000) + this.getAccessTokenExpiryHours() * 3600,
      iat: Math.floor(Date.now() / 1000),
    };

    if (this.isDebugMode()) {
      this.structuredLogger.debug(
        {
          message: 'Access token with JTI payload',
          payloadKeys: Object.keys(payload),
          hasExp: 'exp' in payload,
          hasIat: 'iat' in payload,
          hasJti: 'jti' in payload,
        },
        'TokenService',
      );
    }

    const token = this.signJwt(payload);

    if (this.isDebugMode()) {
      this.structuredLogger.debug(
        {
          message: 'Access token with JTI generated',
          tokenLength: token.length,
        },
        'TokenService',
      );
    }

    return token;
  }

  private generateIdToken(
    user: User,
    client: Client,
    nonce?: string,
    authTime?: number,
  ): string {
    const baseUrl =
      this.configService.get<string>('BACKEND_URL') || 'http://localhost:3000';

    const payload = {
      iss: baseUrl,
      sub: user.id.toString(),
      aud: client.clientId,
      exp: Math.floor(Date.now() / 1000) + 3600, // 1시간
      iat: Math.floor(Date.now() / 1000),
      auth_time: authTime || Math.floor(Date.now() / 1000),
      nonce: nonce,
      email: user.email || '',
      email_verified: !!user.isEmailVerified,
      name: user.username || '',
      preferred_username: user.username || '',
    };

    return this.signJwt(payload);
  }

  private generateRefreshToken(): string {
    return crypto.randomBytes(32).toString('hex');
  }

  async getActiveTokensCountForUser(userId: number): Promise<number> {
    const now = new Date();
    return await this.tokenRepository.count({
      where: {
        user: { id: userId },
        expiresAt: LessThan(now),
        isRevoked: false,
        tokenType: TOKEN_TYPES.OAUTH2,
      },
    });
  }
}
