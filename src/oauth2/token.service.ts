import { Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, LessThan } from 'typeorm';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { Inject } from '@nestjs/common';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import type { Cache } from 'cache-manager';
import { AppConfigService } from '../config/app-config.service';
import { Token } from '../token/token.entity';
import { User } from '../user/user.entity';
import { Client } from '../client/client.entity';
import * as crypto from 'crypto';

interface JwtPayload {
  sub: number | null;
  client_id: string;
  scopes: string[];
  token_type: string;
  iat?: number;
  exp?: number;
}

interface TokenCreateResponse {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
  scopes: string[];
  tokenType: string;
}

@Injectable()
export class TokenService {
  constructor(
    @InjectRepository(Token)
    private readonly tokenRepository: Repository<Token>,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
    @Inject(CACHE_MANAGER) private cacheManager: Cache,
    private readonly appConfig: AppConfigService,
  ) {}

  private getAccessTokenExpiryHours(): number {
    return this.appConfig.accessTokenExpiryHours;
  }

  private getRefreshTokenExpiryDays(): number {
    return this.appConfig.refreshTokenExpiryDays;
  }

  private getAccessTokenExpirySeconds(): number {
    return this.getAccessTokenExpiryHours() * 3600;
  }

  async createToken(
    user: User | null,
    client: Client,
    scopes: string[] = [],
  ): Promise<TokenCreateResponse> {
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
      user: user || null,
      client,
    });

    await this.tokenRepository.save(token);

    return {
      accessToken,
      refreshToken,
      expiresIn: this.getAccessTokenExpirySeconds(),
      scopes,
      tokenType: 'Bearer',
    };
  }

  async refreshToken(
    refreshTokenValue: string,
  ): Promise<TokenCreateResponse | null> {
    // Find token by refresh token
    const token = await this.tokenRepository.findOne({
      where: { refreshToken: refreshTokenValue },
      relations: ['user', 'client'],
    });

    if (!token) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    // Check if refresh token is expired
    if (token.refreshExpiresAt && new Date() > token.refreshExpiresAt) {
      // Remove expired token
      await this.tokenRepository.remove(token);
      throw new UnauthorizedException('Refresh token expired');
    }

    // Generate new access token
    const newAccessToken = this.generateAccessToken(
      token.user,
      token.client,
      token.scopes,
    );
    const newRefreshToken = this.generateRefreshToken();

    const expiresAt = new Date();
    expiresAt.setHours(expiresAt.getHours() + this.getAccessTokenExpiryHours());

    const refreshExpiresAt = new Date();
    refreshExpiresAt.setDate(
      refreshExpiresAt.getDate() + this.getRefreshTokenExpiryDays(),
    );

    // Update token
    token.accessToken = newAccessToken;
    token.refreshToken = newRefreshToken;
    token.expiresAt = expiresAt;
    token.refreshExpiresAt = refreshExpiresAt;

    await this.tokenRepository.save(token);

    return {
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
      expiresIn: this.getAccessTokenExpirySeconds(),
      scopes: token.scopes,
      tokenType: 'Bearer',
    };
  }

  async validateToken(accessToken: string): Promise<JwtPayload | null> {
    try {
      // 캐시에서 먼저 확인
      const cachedToken = await this.cacheManager.get<JwtPayload>(
        `token:${accessToken}`,
      );
      if (cachedToken) {
        return cachedToken;
      }

      const decoded = this.jwtService.verify<JwtPayload>(accessToken);

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
      await this.tokenRepository.remove(token);
    }
  }

  async revokeRefreshToken(refreshToken: string): Promise<void> {
    const token = await this.tokenRepository.findOne({
      where: { refreshToken },
    });

    if (token) {
      await this.tokenRepository.remove(token);
    }
  }

  async revokeAllUserTokens(userId: number): Promise<void> {
    await this.tokenRepository.delete({
      user: { id: userId },
    });
  }

  async revokeAllClientTokens(clientId: string): Promise<void> {
    await this.tokenRepository.delete({
      client: { clientId },
    });
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
    client: Client,
    scopes: string[],
  ): string {
    const payload: JwtPayload = {
      sub: user?.id || null,
      client_id: client.clientId,
      scopes,
      token_type: 'Bearer',
    };

    return this.jwtService.sign(payload, {
      expiresIn: `${this.getAccessTokenExpiryHours()}h`,
    });
  }

  private generateRefreshToken(): string {
    return crypto.randomBytes(32).toString('hex');
  }
}
