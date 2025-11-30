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
import {
  AUTH_CONSTANTS,
  JWT_TOKEN_EXPIRY,
  PERMISSIONS,
  type TokenType,
  TOKEN_EXPIRY_DAYS,
} from '@flowauth/shared';
import { JwtPayload, LoginResponse } from '../../types/auth.types';
import { PermissionUtils } from '../../utils/permission.util';
import { CacheManagerService } from '../../cache/cache-manager.service';
import { randomBytes } from 'crypto';

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
    return await this.tokenRepository.manager.transaction(async (manager) => {
      // Find the refresh token with a lock
      const tokenEntity = await manager.findOne(Token, {
        where: { refreshToken: token },
        relations: ['user'],
        lock: { mode: 'pessimistic_write' },
      });

      if (!tokenEntity) {
        throw new NotFoundException('Refresh token not found');
      }

      if (!tokenEntity.user) {
        throw new NotFoundException('Token user not found');
      }

      // Check if refresh token is expired
      if (
        tokenEntity.refreshExpiresAt &&
        tokenEntity.refreshExpiresAt < new Date()
      ) {
        throw new ForbiddenException('Refresh token expired');
      }

      // Check if refresh token was already used
      if (tokenEntity.isRefreshTokenUsed) {
        // Security: revoke all user tokens if refresh token reuse detected
        await this.revokeAllUserTokens(tokenEntity.user.id);
        throw new ForbiddenException('Refresh token already used');
      }

      // Mark current refresh token as used
      await manager.update(
        Token,
        { id: tokenEntity.id },
        {
          isRefreshTokenUsed: true,
          updatedAt: new Date(),
        },
      );

      // Check if the old access token is expired and delete it to free up resources
      const now = new Date();
      if (
        (tokenEntity.expiresAt && tokenEntity.expiresAt < now) ||
        (tokenEntity.refreshExpiresAt && tokenEntity.refreshExpiresAt < now)
      ) {
        await manager.delete(Token, { id: tokenEntity.id });
      }

      // Generate new refresh token and expiry dates
      const newRefreshToken = randomBytes(32).toString('hex');
      const refreshExpiresAt = new Date();
      refreshExpiresAt.setDate(
        refreshExpiresAt.getDate() + TOKEN_EXPIRY_DAYS.REFRESH_TOKEN,
      );

      const newExpiresAt = new Date();
      newExpiresAt.setSeconds(
        newExpiresAt.getSeconds() + AUTH_CONSTANTS.TOKEN_EXPIRATION_SECONDS,
      );

      // Create new token with updated family generation (initially with empty access token)
      const newTokenEntity = manager.create(Token, {
        accessToken: '', // Will be updated with final JWT
        refreshToken: newRefreshToken,
        expiresAt: newExpiresAt,
        refreshExpiresAt,
        scopes: tokenEntity.scopes,
        user: tokenEntity.user,
        tokenType: tokenEntity.tokenType,
        tokenFamily: tokenEntity.tokenFamily,
        rotationGeneration: (tokenEntity.rotationGeneration || 1) + 1,
        isRefreshTokenUsed: false,
      });

      await manager.save(newTokenEntity);

      // Generate final JWT with NEW token ID for revocation capability
      const finalPayload: JwtPayload = {
        sub: tokenEntity.user.id.toString(),
        email: tokenEntity.user.email,
        username: tokenEntity.user.username,
        roles: [PermissionUtils.getRoleName(tokenEntity.user.permissions)],
        permissions: tokenEntity.user.permissions,
        type: tokenEntity.tokenType,
        avatar: tokenEntity.user.avatar ?? undefined,
        jti: newTokenEntity.id.toString(),
      };

      const finalAccessToken = this.jwtService.sign(finalPayload, {
        expiresIn: `${JWT_TOKEN_EXPIRY.LOGIN_HOURS}h`,
      });

      // Update token with final access token
      newTokenEntity.accessToken = finalAccessToken;
      await manager.save(newTokenEntity);

      return {
        user: tokenEntity.user,
        accessToken: finalAccessToken,
        refreshToken: newRefreshToken,
        expiresIn: AUTH_CONSTANTS.TOKEN_EXPIRATION_SECONDS,
      };
    });
  }
}
