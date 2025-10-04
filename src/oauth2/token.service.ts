import { Injectable, UnauthorizedException, Inject } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, LessThan } from 'typeorm';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import type { Cache } from 'cache-manager';
import * as jwt from 'jsonwebtoken';
import * as crypto from 'crypto';
import axios from 'axios';
import { AppConfigService } from '../config/app-config.service';
import { Token } from './token.entity';
import { User } from '../auth/user.entity';
import { Client } from './client.entity';
import { OAuth2JwtPayload } from '../types/oauth2.types';
import { JWT_CONSTANTS, CACHE_CONSTANTS } from '../constants/jwt.constants';
import { StructuredLogger } from '../logging/structured-logger.service';
import { TOKEN_TYPES, JWT_TOKEN_EXPIRY } from '../constants/auth.constants';

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
  auth_time?: number;
  nonce?: string;
  email?: string;
  email_verified?: boolean;
  name?: string;
  preferred_username?: string;
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
    return (
      this.getAccessTokenExpiryHours() * JWT_CONSTANTS.TIME.ONE_HOUR_SECONDS
    );
  }

  private getJwtSecret(): string {
    return (
      this.configService.get<string>('JWT_SECRET') ||
      JWT_CONSTANTS.SECRET_KEY_FALLBACK
    );
  }

  private signJwt(payload: Record<string, any>): string {
    const secret = this.getJwtSecret();
    return jwt.sign(payload, secret);
  }

  private async signJwtWithRSA(payload: Record<string, any>): Promise<string> {
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
        tokenType: JWT_CONSTANTS.TOKEN_TYPE,
      };

      // Generate ID token if openid scope is requested and user exists
      if (user && scopes.includes('openid')) {
        response.idToken = await this.generateIdToken(
          user,
          client,
          nonce,
          authTime,
        );
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
      token_type: JWT_CONSTANTS.TOKEN_TYPE,
      exp:
        Math.floor(Date.now() / 1000) +
        this.getAccessTokenExpiryHours() * JWT_CONSTANTS.TIME.ONE_HOUR_SECONDS,
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
      token_type: JWT_CONSTANTS.TOKEN_TYPE,
      jti: tokenId.toString(),
      exp:
        Math.floor(Date.now() / 1000) +
        this.getAccessTokenExpiryHours() * JWT_CONSTANTS.TIME.ONE_HOUR_SECONDS,
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

  private async generateIdToken(
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

    return await this.signJwtWithRSA(payload);
  }

  /**
   * JWKS에서 RSA 공개키 가져오기
   * @param kid Key ID
   * @returns RSA 공개키
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

      // JWK를 PEM 형식으로 변환
      const modulus = Buffer.from(key.n, 'base64url');
      const exponent = Buffer.from(key.e, 'base64url');

      const publicKeyDer = this.jwkToDer(modulus, exponent);
      return crypto.createPublicKey({
        key: publicKeyDer,
        format: 'der',
        type: 'spki',
      });
    } catch (error) {
      this.structuredLogger.error(
        {
          message: 'Failed to fetch RSA public key',
          kid,
          error: error instanceof Error ? error.message : 'Unknown error',
        },
        'TokenService',
      );
      throw new Error('Failed to fetch RSA public key');
    }
  } /**
   * JWK를 DER 형식으로 변환
   */
  private jwkToDer(modulus: Buffer, exponent: Buffer): Buffer {
    // RSA 공개키 DER 인코딩
    const modulusLength = modulus.length;
    const exponentLength = exponent.length;

    // DER 시퀀스: SEQUENCE { INTEGER (modulus), INTEGER (exponent) }
    const totalLength = 4 + modulusLength + 2 + exponentLength;
    const buffer = Buffer.alloc(totalLength + 2); // +2 for outer sequence

    let offset = 0;
    buffer.writeUInt8(0x30, offset++); // SEQUENCE
    buffer.writeUInt8(totalLength, offset++); // Length

    // Modulus
    buffer.writeUInt8(0x02, offset++); // INTEGER
    buffer.writeUInt8(modulusLength, offset++); // Length
    modulus.copy(buffer, offset);
    offset += modulusLength;

    // Exponent
    buffer.writeUInt8(0x02, offset++); // INTEGER
    buffer.writeUInt8(exponentLength, offset++); // Length
    exponent.copy(buffer, offset);

    return buffer;
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
          'TokenService',
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

      const publicKey = await this.getRsaPublicKey(kid);

      // 서명 검증
      const data = `${parts[0]}.${parts[1]}`;
      const signatureBuffer = Buffer.from(signature, 'base64url');
      const isValidSignature = crypto.verify(
        'RSA-SHA256',
        Buffer.from(data),
        publicKey,
        signatureBuffer,
      );

      if (!isValidSignature) {
        throw new Error('Invalid RSA signature');
      }

      // 클레임 검증
      const baseUrl =
        this.configService.get<string>('BACKEND_URL') ||
        'http://localhost:3000';
      const now = Math.floor(Date.now() / 1000);

      // Issuer 검증
      if (payload.iss !== baseUrl) {
        throw new Error('Invalid issuer');
      }

      // Audience 검증
      if (payload.aud !== expectedClientId) {
        throw new Error('Invalid audience');
      }

      // 만료시간 검증
      if (payload.exp < now) {
        throw new Error('Token expired');
      }

      // 발급시간 검증 (미래 발급 불가)
      if (payload.iat > now) {
        throw new Error('Token issued in future');
      }

      // Nonce 검증 (제공된 경우)
      if (expectedNonce && payload.nonce !== expectedNonce) {
        throw new Error('Invalid nonce');
      }

      this.structuredLogger.debug(
        {
          message: 'ID token validation successful',
          sub: payload.sub,
          aud: payload.aud,
          exp: new Date(payload.exp * 1000).toISOString(),
        },
        'TokenService',
      );

      return payload;
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
