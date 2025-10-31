import {
  Injectable,
  NotFoundException,
  ForbiddenException,
  Logger,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { JwtService } from '@nestjs/jwt';
import { User } from '../user.entity';
import { Token } from '../../oauth2/token.entity';
import { TokenDto } from '../dto/response.dto';
import * as crypto from 'crypto';
import {
  AUTH_CONSTANTS,
  JWT_TOKEN_EXPIRY,
  PERMISSIONS,
  type TokenType,
} from '../../constants/auth.constants';
import { JwtPayload, LoginResponse } from '../../types/auth.types';
import { PermissionUtils } from '../../utils/permission.util';
import { CacheManagerService } from '../../cache/cache-manager.service';

@Injectable()
export class TokenAuthService {
  private readonly logger = new Logger(TokenAuthService.name);

  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
    @InjectRepository(Token)
    private tokenRepository: Repository<Token>,
    private jwtService: JwtService,
    private cacheManagerService: CacheManagerService,
  ) {}

  async getUserTokens(userId: number): Promise<TokenDto[]> {
    const tokens = await this.tokenRepository.find({
      where: { user: { id: userId } },
      relations: ['client', 'user'],
      order: { createdAt: 'DESC' },
    });

    return tokens.map((token) => ({
      id: token.id,
      tokenType: token.tokenType,
      expiresAt: token.expiresAt.toISOString(),
      refreshExpiresAt: token.refreshExpiresAt?.toISOString(),
      scopes: token.scopes,
      userId: token.user?.id ?? 0,
      clientId: token.client?.id,
      client: token.client
        ? {
            name: token.client.name,
            clientId: token.client.clientId,
          }
        : undefined,
      createdAt: token.createdAt.toISOString(),
      updatedAt: token.updatedAt.toISOString(),
    }));
  }

  async revokeToken(userId: number, tokenId: number): Promise<void> {
    const token = await this.tokenRepository.findOne({
      where: { id: tokenId, user: { id: userId } },
      relations: ['user'],
    });

    if (!token) {
      throw new NotFoundException('Token not found or access denied');
    }

    if (!token.user) {
      throw new NotFoundException('Token user not found');
    }

    // Check if user has permission to revoke tokens (자신의 토큰 삭제)
    if (
      !PermissionUtils.hasPermission(
        token.user.permissions,
        PERMISSIONS.DELETE_TOKEN,
      )
    ) {
      throw new ForbiddenException('Insufficient permissions');
    }

    // Mark token as revoked by setting access token to null or a special marker
    token.accessToken = 'REVOKED';
    token.isRefreshTokenUsed = true;
    await this.tokenRepository.save(token);

    // Clear any cached data related to this token
    await this.cacheManagerService.delCacheKey(`token:${tokenId}`);
  }

  async revokeAllUserTokens(userId: number): Promise<void> {
    const user = await this.userRepository.findOne({
      where: { id: userId },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    // Check if user has permission to revoke tokens (자신의 모든 토큰 삭제)
    if (
      !PermissionUtils.hasPermission(user.permissions, PERMISSIONS.DELETE_TOKEN)
    ) {
      throw new ForbiddenException('Insufficient permissions');
    }

    // Mark all user tokens as revoked
    await this.tokenRepository.update(
      { user: { id: userId } },
      { accessToken: 'REVOKED', isRefreshTokenUsed: true },
    );

    // Clear user-related cache
    await this.cacheManagerService.delCacheKey(`tokens:${userId}`);
  }

  async revokeAllTokensForType(
    userId: number,
    tokenType: TokenType,
  ): Promise<void> {
    const user = await this.userRepository.findOne({
      where: { id: userId },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    // Check if user has permission to revoke tokens (자신의 특정 타입 토큰 삭제)
    if (
      !PermissionUtils.hasPermission(user.permissions, PERMISSIONS.DELETE_TOKEN)
    ) {
      throw new ForbiddenException('Insufficient permissions');
    }

    // Mark all tokens of specific type as revoked
    await this.tokenRepository.update(
      { user: { id: userId }, tokenType },
      { accessToken: 'REVOKED', isRefreshTokenUsed: true },
    );
  }

  async refreshToken(token: string): Promise<LoginResponse> {
    try {
      // Find the refresh token
      const tokenEntity = await this.tokenRepository.findOne({
        where: { refreshToken: token },
        relations: ['user'],
      });

      if (!tokenEntity) {
        throw new NotFoundException('Refresh token not found');
      }

      if (!tokenEntity.user) {
        throw new NotFoundException('Token user not found');
      }

      if (!tokenEntity.refreshExpiresAt) {
        throw new ForbiddenException('Refresh token expired');
      }

      // Check if token is expired
      if (tokenEntity.refreshExpiresAt < new Date()) {
        throw new ForbiddenException('Refresh token expired');
      }

      // Check if refresh token was already used
      if (tokenEntity.isRefreshTokenUsed) {
        // Security: revoke all user tokens if refresh token reuse detected
        await this.revokeAllUserTokens(tokenEntity.user.id);
        throw new ForbiddenException('Refresh token already used');
      }

      // Mark refresh token as used
      tokenEntity.isRefreshTokenUsed = true;
      await this.tokenRepository.save(tokenEntity);

      // Generate new access token
      const payload: JwtPayload = {
        sub: tokenEntity.user.id.toString(),
        email: tokenEntity.user.email,
        username: tokenEntity.user.username,
        roles: [PermissionUtils.getRoleName(tokenEntity.user.permissions)],
        permissions: tokenEntity.user.permissions,
        type: tokenEntity.tokenType,
        avatar: tokenEntity.user.avatar ?? undefined,
        jti: tokenEntity.id.toString(),
      };

      const newAccessToken = this.jwtService.sign(payload, {
        expiresIn: `${JWT_TOKEN_EXPIRY.LOGIN_HOURS}h`,
      });

      // Generate new refresh token
      const newRefreshToken = crypto.randomBytes(32).toString('hex');
      const refreshExpiresAt = new Date();
      refreshExpiresAt.setDate(refreshExpiresAt.getDate() + 30);

      // Create new token entity
      const newTokenEntity = this.tokenRepository.create({
        accessToken: newAccessToken,
        refreshToken: newRefreshToken,
        expiresAt: new Date(
          Date.now() + AUTH_CONSTANTS.TOKEN_EXPIRATION_SECONDS * 1000,
        ),
        refreshExpiresAt,
        scopes: tokenEntity.scopes,
        user: tokenEntity.user,
        tokenType: tokenEntity.tokenType,
        isRefreshTokenUsed: false,
      });

      await this.tokenRepository.save(newTokenEntity);

      return {
        user: tokenEntity.user,
        accessToken: newAccessToken,
        refreshToken: newRefreshToken,
        expiresIn: AUTH_CONSTANTS.TOKEN_EXPIRATION_SECONDS,
      };
    } catch (error) {
      this.logger.error('Token refresh failed:', error);
      throw error;
    }
  }
}
