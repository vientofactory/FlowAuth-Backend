import { Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { JwtService } from '@nestjs/jwt';
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
  private static readonly ACCESS_TOKEN_EXPIRY_HOURS = 1;
  private static readonly REFRESH_TOKEN_EXPIRY_DAYS = 30;
  private static readonly ACCESS_TOKEN_EXPIRY_SECONDS =
    TokenService.ACCESS_TOKEN_EXPIRY_HOURS * 86400;

  constructor(
    @InjectRepository(Token)
    private readonly tokenRepository: Repository<Token>,
    private readonly jwtService: JwtService,
  ) {}

  async createToken(
    user: User | null,
    client: Client,
    scopes: string[] = [],
  ): Promise<TokenCreateResponse> {
    const accessToken = this.generateAccessToken(user, client, scopes);
    const refreshToken = this.generateRefreshToken();

    const expiresAt = new Date();
    expiresAt.setHours(
      expiresAt.getHours() + TokenService.ACCESS_TOKEN_EXPIRY_HOURS,
    );

    const refreshExpiresAt = new Date();
    refreshExpiresAt.setDate(
      refreshExpiresAt.getDate() + TokenService.REFRESH_TOKEN_EXPIRY_DAYS,
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
      expiresIn: TokenService.ACCESS_TOKEN_EXPIRY_SECONDS,
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
    expiresAt.setHours(
      expiresAt.getHours() + TokenService.ACCESS_TOKEN_EXPIRY_HOURS,
    );

    const refreshExpiresAt = new Date();
    refreshExpiresAt.setDate(
      refreshExpiresAt.getDate() + TokenService.REFRESH_TOKEN_EXPIRY_DAYS,
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
      expiresIn: TokenService.ACCESS_TOKEN_EXPIRY_SECONDS,
      scopes: token.scopes,
      tokenType: 'Bearer',
    };
  }

  async validateToken(accessToken: string): Promise<JwtPayload | null> {
    try {
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
      expiresIn: `${TokenService.ACCESS_TOKEN_EXPIRY_HOURS}h`,
    });
  }

  private generateRefreshToken(): string {
    return crypto.randomBytes(32).toString('hex');
  }
}
