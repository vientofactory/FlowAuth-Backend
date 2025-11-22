import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, EntityManager } from 'typeorm';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import * as crypto from 'crypto';
import { User } from '../../auth/user.entity';
import { Client } from '../client.entity';
import { Token } from '../token.entity';
import { JWT_CONSTANTS } from '../../constants/jwt.constants';
import { TOKEN_TYPES } from '@flowauth/shared';
import { IdTokenService } from './id-token.service';
import { safeTokenCompare } from '../../utils/timing-security.util';
import { AuditLogService } from '../../common/audit-log.service';
import { AuditLog } from '../../common/audit-log.entity';
import { StatisticsEventService } from '../../common/statistics-event.service';
import { CacheManagerService } from '../../cache/cache-manager.service';

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
  private readonly logger = new Logger(OAuth2TokenService.name);

  constructor(
    @InjectRepository(Token)
    private tokenRepository: Repository<Token>,
    private jwtService: JwtService,
    private configService: ConfigService,
    private idTokenService: IdTokenService,
    private auditLogService: AuditLogService,
    private statisticsEventService: StatisticsEventService,
    private cacheManagerService: CacheManagerService,
  ) {}

  async createToken(
    user: User | null,
    client: Client,
    scopes: string[] = [],
    nonce?: string,
    authTime?: number,
  ): Promise<TokenCreateResponse> {
    return this.tokenRepository.manager.transaction(async (manager) => {
      // Debug logging only in development environment
      if (this.isDebugMode() && process.env.NODE_ENV === 'development') {
        this.logger.debug(
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
        user: user ?? undefined,
        client,
        tokenType: TOKEN_TYPES.OAUTH2,
        tokenFamily,
        rotationGeneration: 1,
      });

      await manager.save(Token, token);

      // Record statistics event
      if (user) {
        try {
          await this.statisticsEventService.recordTokenIssued(
            user.id,
            client.id,
            scopes,
            new Date(),
          );
        } catch (error) {
          this.logger.error(error, 'OAuth2TokenService', {
            operation: 'recordTokenStatistics',
            userId: user.id,
            clientId: client.id,
          });
        }
      }

      // Create audit log entry
      if (user) {
        try {
          await this.auditLogService.create(
            AuditLog.createTokenIssuedEvent(
              user.id,
              client.id,
              scopes,
              undefined, // TODO: Implement IP address retrieval
            ),
          );
        } catch (error) {
          this.logger.error(error, 'OAuth2TokenService', {
            operation: 'createAuditLog',
            userId: user.id,
            clientId: client.id,
          });
        }
      }

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
          this.logger.error(error, 'OAuth2TokenService', {
            operation: 'generateIdToken',
            userId: user.id,
            clientId: client.clientId,
          });
        }
      }

      return response;
    });
  }

  /**
   * Create tokens for Implicit Grant flow (OpenID Connect)
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

    // Create tokens based on requested scopes
    if (scopes.includes('openid')) {
      const accessToken = this.generateAccessToken(user, client, scopes);
      response.accessToken = accessToken;
      response.expiresIn = this.getAccessTokenExpirySeconds();

      // Generate auth time
      const authTime = Math.floor(Date.now() / 1000);
      response.idToken = await this.generateIdToken(
        user,
        client,
        scopes,
        nonce,
        authTime,
      );
    } else {
      // Only access token if openid scope is not requested
      const accessToken = this.generateAccessToken(user, client, scopes);
      response.accessToken = accessToken;
      response.expiresIn = this.getAccessTokenExpirySeconds();
    }

    return response;
  }

  /**
   * Issue new tokens using a refresh token
   * Implements robust handling to prevent race conditions
   */
  async refreshToken(
    refreshTokenValue: string,
    clientId: string,
  ): Promise<TokenCreateResponse | null> {
    // Use transaction with pessimistic locking to prevent race conditions
    return await this.tokenRepository.manager.transaction(async (manager) => {
      // Find the token by refresh token value with a lock
      const token = await manager.findOne(Token, {
        where: { refreshToken: refreshTokenValue },
        relations: ['user', 'client'],
        lock: { mode: 'pessimistic_write' },
      });

      if (!token) {
        return null;
      }

      if (!token.client) {
        return null;
      }

      // Verify client matches using timing-safe comparison
      if (clientId && !safeTokenCompare(token.client.clientId, clientId)) {
        return null;
      }

      // Check if refresh token is expired
      if (token.refreshExpiresAt && token.refreshExpiresAt < new Date()) {
        return null;
      }

      // Check if token or its family is revoked
      if (token.isRefreshTokenUsed) {
        // Enhanced Security: revoke entire token family if refresh token reuse detected
        await this.revokeTokenFamilyInTransaction(
          manager,
          token.tokenFamily,
          'refresh_token_reuse',
        );

        this.logger.warn('refresh_token_reuse_detected', {
          tokenFamily: token.tokenFamily,
          generation: token.rotationGeneration,
          clientId: token.client.clientId,
          userId: token.user?.id,
        });

        return null;
      }

      // Mark current refresh token as used
      await manager.update(
        Token,
        { id: token.id },
        {
          isRefreshTokenUsed: true,
          updatedAt: new Date(),
        },
      );

      // Generate new refresh token and expiry dates
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
        accessToken: '',
        refreshToken: newRefreshToken,
        expiresAt: newExpiresAt,
        refreshExpiresAt: newRefreshExpiresAt,
        scopes: token.scopes,
        user: token.user ?? undefined,
        client: token.client,
        tokenType: TOKEN_TYPES.OAUTH2,
        tokenFamily: token.tokenFamily,
        rotationGeneration: (token.rotationGeneration || 1) + 1,
        isRefreshTokenUsed: false,
      });

      await manager.save(newToken);

      // Generate new access token with new token ID for revocation capability
      const newAccessToken = this.generateAccessTokenWithJti(
        token.user ?? null,
        token.client,
        token.scopes ?? [],
        newToken.id,
      );

      // Update token with final access token
      newToken.accessToken = newAccessToken;
      await manager.save(newToken);

      return {
        accessToken: newAccessToken,
        refreshToken: newRefreshToken,
        expiresIn: this.getAccessTokenExpirySeconds(),
        scopes: token.scopes ?? [],
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
      sub: user?.id?.toString() ?? client.clientId,
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
      sub: user?.id?.toString() ?? client.clientId,
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
    return this.configService.get<number>('ACCESS_TOKEN_EXPIRY_HOURS') ?? 1;
  }

  private getRefreshTokenExpiryDays(): number {
    return this.configService.get<number>('REFRESH_TOKEN_EXPIRY_DAYS') ?? 30;
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

  /**
   * Token family revocation within a transaction context
   */
  private async revokeTokenFamilyInTransaction(
    manager: EntityManager,
    tokenFamily: string | undefined,
    reason: string,
  ): Promise<void> {
    if (!tokenFamily) return;

    // Get all tokens in family before revoking
    const tokensInFamily = await manager.find(Token, {
      where: { tokenFamily },
      select: ['id'],
    });

    await manager.update(
      Token,
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
      await this.cacheManagerService.delCacheKey(`oauth2_token:${token.id}`);
    }
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
