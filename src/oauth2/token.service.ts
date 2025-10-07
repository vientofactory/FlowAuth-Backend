import { Injectable, UnauthorizedException, Inject } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, LessThan } from 'typeorm';
import { JwtService } from '@nestjs/jwt';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import type { Cache } from 'cache-manager';
import { Token } from './token.entity';
import { User } from '../auth/user.entity';
import { Client } from './client.entity';
import { OAuth2JwtPayload } from '../types/oauth2.types';
import { CACHE_CONSTANTS } from '../constants/jwt.constants';
import { StructuredLogger } from '../logging/structured-logger.service';
import { TOKEN_TYPES } from '../constants/auth.constants';
import { OAuth2TokenService } from './services/oauth2-token.service';
import { TokenRevocationService } from './services/token-revocation.service';
import { IdTokenService } from './services/id-token.service';

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
    @Inject(CACHE_MANAGER)
    private readonly cacheManager: Cache,
    private readonly structuredLogger: StructuredLogger,
    private readonly oauth2TokenService: OAuth2TokenService,
    private readonly tokenRevocationService: TokenRevocationService,
    private readonly idTokenService: IdTokenService,
  ) {}
  async createToken(
    user: User | null,
    client: Client,
    scopes: string[] = [],
    nonce?: string,
    authTime?: number,
  ): Promise<TokenCreateResponse> {
    return this.oauth2TokenService.createToken(
      user,
      client,
      scopes,
      nonce,
      authTime,
    );
  }

  async createImplicitTokens(
    user: User,
    client: Client,
    scopes: string[],
    nonce?: string,
  ): Promise<ImplicitTokenResponse> {
    return this.oauth2TokenService.createImplicitTokens(
      user,
      client,
      scopes,
      nonce,
    );
  }

  async refreshToken(
    refreshTokenValue: string,
    clientId: string,
  ): Promise<TokenCreateResponse | null> {
    return this.oauth2TokenService.refreshToken(refreshTokenValue, clientId);
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
      await this.cacheManager.set(
        `token:${accessToken}`,
        decoded,
        CACHE_CONSTANTS.TOKEN_VALIDATION_TTL,
      );

      return decoded;
    } catch {
      return null;
    }
  }

  async revokeToken(accessToken: string): Promise<void> {
    return this.tokenRevocationService.revokeToken(accessToken);
  }

  async revokeRefreshToken(refreshToken: string): Promise<void> {
    return this.tokenRevocationService.revokeRefreshToken(refreshToken);
  }

  async revokeAllUserTokens(userId: number): Promise<void> {
    return this.tokenRevocationService.revokeAllUserTokens(userId);
  }

  async revokeAllClientTokens(clientId: string): Promise<void> {
    return this.tokenRevocationService.revokeAllClientTokens(clientId);
  }

  async cleanupExpiredTokens(): Promise<number> {
    return this.tokenRevocationService.cleanupExpiredTokens();
  }

  async generateIdToken(
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
   * ID 토큰 검증 (RSA 서명 + 클레임 검증)
   * @param idToken ID 토큰
   * @param expectedClientId 예상 클라이언트 ID
   * @param expectedNonce 예상 nonce (선택사항)
   * @returns 검증된 토큰 페이로드
   */
  async validateIdToken(
    idToken: string,
    expectedClientId: string,
    expectedNonce?: string,
  ): Promise<any> {
    try {
      return await this.idTokenService.validateIdToken(
        idToken,
        expectedClientId,
        expectedNonce,
      );
    } catch (error) {
      this.structuredLogger.error(
        {
          message: 'ID token validation failed',
          error: error instanceof Error ? error.message : 'Unknown error',
          expectedClientId,
        },
        'TokenService',
      );
      throw new UnauthorizedException(
        `ID token validation failed: ${
          error instanceof Error ? error.message : 'Unknown error'
        }`,
      );
    }
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
