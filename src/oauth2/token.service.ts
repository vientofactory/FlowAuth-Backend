import { Injectable } from '@nestjs/common';
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
}

@Injectable()
export class TokenService {
  private static readonly ACCESS_TOKEN_EXPIRY_HOURS = 1;
  private static readonly REFRESH_TOKEN_EXPIRY_DAYS = 30;

  constructor(
    @InjectRepository(Token)
    private readonly tokenRepository: Repository<Token>,
    private readonly jwtService: JwtService,
  ) {}

  async createToken(
    user: User | null,
    client: Client,
    scopes: string[] = [],
  ): Promise<Token> {
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
      tokenType: 'bearer',
      user: user || undefined,
      client,
    });

    return this.tokenRepository.save(token);
  }

  async refreshToken(refreshToken: string): Promise<Token | null> {
    const token = await this.tokenRepository.findOne({
      where: { refreshToken, isRevoked: false },
      relations: ['user', 'client'],
    });

    if (!token || token.refreshExpiresAt < new Date()) {
      return null;
    }

    // Revoke old token
    token.isRevoked = true;
    await this.tokenRepository.save(token);

    // Create new token
    return this.createToken(token.user, token.client, token.scopes);
  }

  async validateToken(accessToken: string): Promise<Token | null> {
    const token = await this.tokenRepository.findOne({
      where: { accessToken, isRevoked: false },
      relations: ['user', 'client'],
    });

    if (!token || token.expiresAt < new Date()) {
      return null;
    }

    return token;
  }

  async revokeToken(accessToken: string): Promise<boolean> {
    const result = await this.tokenRepository.update(
      { accessToken },
      { isRevoked: true },
    );

    return (result.affected ?? 0) > 0;
  }

  private generateAccessToken(
    user: User | null,
    client: Client,
    scopes: string[],
  ): string {
    const payload: JwtPayload = {
      sub: user ? user.id : null,
      client_id: client.clientId,
      scopes,
      token_type: 'access_token',
    };

    return this.jwtService.sign(payload);
  }

  private generateRefreshToken(): string {
    return crypto.randomBytes(64).toString('hex');
  }
}
