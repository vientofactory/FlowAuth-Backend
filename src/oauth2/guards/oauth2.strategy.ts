import { Injectable, UnauthorizedException, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Strategy, ExtractJwt, StrategyOptions } from 'passport-jwt';
import { Token } from '../token.entity';
import { AUTH_ERROR_MESSAGES } from '@flowauth/shared';
import { CACHE_CONFIG } from '../../constants/cache.constants';
import { OAuth2JwtPayload } from '../../types/oauth2.types';
import { CacheManagerService } from '../../cache/cache-manager.service';

@Injectable()
export class OAuth2Strategy extends PassportStrategy(Strategy, 'oauth2') {
  private readonly logger = new Logger(OAuth2Strategy.name);

  constructor(
    @InjectRepository(Token)
    private tokenRepository: Repository<Token>,
    private configService: ConfigService,
    private cacheManagerService: CacheManagerService,
  ) {
    const jwtSecret = configService.get<string>('JWT_SECRET') ?? '';

    const options: StrategyOptions = {
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: jwtSecret,
    };

    super(options);
  }

  async validate(payload: OAuth2JwtPayload): Promise<OAuth2JwtPayload> {
    try {
      // If jti is present, verify token exists in database (for revocation check)
      if (payload.jti) {
        // Validate that jti is a valid numeric string
        if (typeof payload.jti !== 'string' || isNaN(Number(payload.jti))) {
          throw new UnauthorizedException(AUTH_ERROR_MESSAGES.INVALID_TOKEN);
        }

        const tokenId = parseInt(payload.jti, 10);

        // Try to get token validation result from cache first
        const validationCacheKey = `oauth2_validation:${tokenId}`;
        let isValidToken =
          await this.cacheManagerService.getCacheValue<boolean>(
            validationCacheKey,
          );

        let token: Token | null = null;

        if (isValidToken === undefined) {
          // Cache miss - fetch from database with relations
          token = await this.tokenRepository.findOne({
            where: { id: tokenId },
            relations: ['client'],
          });

          if (
            token &&
            !token.isRevoked &&
            token.expiresAt > new Date() &&
            token.client
          ) {
            isValidToken = true;
            // Cache the validation result
            await this.cacheManagerService.setCacheValue(
              validationCacheKey,
              true,
              CACHE_CONFIG.TTL.TOKEN_VALIDATION,
            );
          } else {
            isValidToken = false;
            // Cache negative result for shorter duration to avoid repeated DB calls
            await this.cacheManagerService.setCacheValue(
              validationCacheKey,
              false,
              Math.min(CACHE_CONFIG.TTL.TOKEN_VALIDATION, 300), // Max 5 minutes for negative cache
            );
          }
        } else if (isValidToken === true) {
          // Token is cached as valid, but we still need to fetch it with relations for verification
          token = await this.tokenRepository.findOne({
            where: { id: tokenId },
            relations: ['client'],
          });
        }

        if (!token) {
          throw new UnauthorizedException(AUTH_ERROR_MESSAGES.INVALID_TOKEN);
        }

        if (!token.client) {
          throw new UnauthorizedException(AUTH_ERROR_MESSAGES.INVALID_TOKEN);
        }

        // Verify token belongs to the client
        if (payload.client_id && token.client.clientId !== payload.client_id) {
          throw new UnauthorizedException(AUTH_ERROR_MESSAGES.INVALID_TOKEN);
        }

        // Verify token is not revoked and not expired
        if (token.isRevoked || token.expiresAt < new Date()) {
          throw new UnauthorizedException(AUTH_ERROR_MESSAGES.INVALID_TOKEN);
        }

        // Add scopes from token to payload for scope validation
        payload.scopes = token.scopes ?? [];
      }

      return payload;
    } catch (error: unknown) {
      if (error instanceof UnauthorizedException) {
        throw error;
      }

      this.logger.error('Unexpected error during OAuth2 token validation', {
        error,
      });
      throw new UnauthorizedException(AUTH_ERROR_MESSAGES.INVALID_TOKEN);
    }
  }
}
