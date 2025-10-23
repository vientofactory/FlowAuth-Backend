import {
  Injectable,
  UnauthorizedException,
  Logger,
  Inject,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Strategy, ExtractJwt, StrategyOptions } from 'passport-jwt';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import type { Cache } from 'cache-manager';
import { Token } from '../token.entity';
import { AUTH_ERROR_MESSAGES } from '../../constants/auth.constants';
import { OAuth2JwtPayload } from '../../types/oauth2.types';

@Injectable()
export class OAuth2Strategy extends PassportStrategy(Strategy, 'oauth2') {
  private readonly logger = new Logger(OAuth2Strategy.name);
  private readonly TOKEN_CACHE_TTL = 300; // 5 minutes cache for token validation

  constructor(
    @InjectRepository(Token)
    private tokenRepository: Repository<Token>,
    private configService: ConfigService,
    @Inject(CACHE_MANAGER)
    private cacheManager: Cache,
  ) {
    const jwtSecret =
      configService.get<string>('JWT_SECRET') || 'your-secret-key';

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
          this.logger.warn('Invalid jti format in OAuth2 payload', {
            jti: payload.jti,
          });
          throw new UnauthorizedException(AUTH_ERROR_MESSAGES.INVALID_TOKEN);
        }

        const tokenId = parseInt(payload.jti, 10);
        const cacheKey = `oauth2_token:${tokenId}`;

        // Try to get token from cache first
        let token = await this.cacheManager.get<Token>(cacheKey);

        if (!token) {
          // Cache miss - fetch from database
          const dbToken = await this.tokenRepository.findOne({
            where: { id: tokenId },
            relations: ['client'],
          });

          if (dbToken) {
            token = dbToken;
            // Cache the token if found and valid
            if (!token.isRevoked && token.expiresAt > new Date()) {
              await this.cacheManager.set(
                cacheKey,
                token,
                this.TOKEN_CACHE_TTL,
              );
            }
          }
        }

        if (!token) {
          this.logger.warn('OAuth2 token not found in database', {
            jti: payload.jti,
          });
          throw new UnauthorizedException(AUTH_ERROR_MESSAGES.INVALID_TOKEN);
        }

        if (!token.client) {
          this.logger.warn('OAuth2 token has no associated client', {
            jti: payload.jti,
          });
          throw new UnauthorizedException(AUTH_ERROR_MESSAGES.INVALID_TOKEN);
        }

        // Verify token belongs to the client
        if (payload.client_id && token.client.clientId !== payload.client_id) {
          this.logger.warn('OAuth2 token client mismatch', {
            jti: payload.jti,
            payloadClientId: payload.client_id,
            tokenClientId: token.client.clientId,
          });
          throw new UnauthorizedException(AUTH_ERROR_MESSAGES.INVALID_TOKEN);
        }

        // Verify token is not revoked and not expired
        if (token.isRevoked || token.expiresAt < new Date()) {
          this.logger.warn('OAuth2 token is revoked or expired', {
            jti: payload.jti,
            isRevoked: token.isRevoked,
            expiresAt: token.expiresAt,
          });
          throw new UnauthorizedException(AUTH_ERROR_MESSAGES.INVALID_TOKEN);
        }

        // Add scopes from token to payload for scope validation
        payload.scopes = token.scopes || [];
      } else {
        // For implicit grant tokens without jti, extract scopes from JWT payload
        // Implicit grant tokens are not stored in database but have scopes in JWT
        if (payload.scope && typeof payload.scope === 'string') {
          payload.scopes = payload.scope.split(' ').filter((s) => s.length > 0);
        } else if (payload.scopes?.length === 0) {
          this.logger.warn('OAuth2 token without jti has no scopes', {
            clientId: payload.client_id,
            sub: payload.sub,
          });
          // Default to basic scopes if none found
          payload.scopes = [];
        }
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
