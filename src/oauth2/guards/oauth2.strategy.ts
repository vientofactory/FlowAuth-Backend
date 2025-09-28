import { Injectable, UnauthorizedException, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Strategy, ExtractJwt, StrategyOptions } from 'passport-jwt';
import { Token } from '../../token/token.entity';
import { AUTH_ERROR_MESSAGES } from '../../constants/auth.constants';
import { OAuth2JwtPayload } from '../../types/oauth2.types';

@Injectable()
export class OAuth2Strategy extends PassportStrategy(Strategy, 'oauth2') {
  private readonly logger = new Logger(OAuth2Strategy.name);
  constructor(
    @InjectRepository(Token)
    private tokenRepository: Repository<Token>,
    private configService: ConfigService,
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
      this.logger.debug('Validating OAuth2 token payload', {
        sub: payload.sub,
        client_id: payload.client_id,
        scopes: payload.scopes,
        token_type: payload.token_type,
        hasJti: !!payload.jti,
      });

      // If jti is present, verify token exists in database (for revocation check)
      if (payload.jti) {
        this.logger.debug('Checking jti in database', { jti: payload.jti });

        // Validate that jti is a valid numeric string
        if (typeof payload.jti !== 'string' || isNaN(Number(payload.jti))) {
          this.logger.warn('Invalid jti format in OAuth2 payload', {
            jti: payload.jti,
          });
          throw new UnauthorizedException(AUTH_ERROR_MESSAGES.INVALID_TOKEN);
        }

        const tokenId = parseInt(payload.jti, 10);
        const token = await this.tokenRepository.findOne({
          where: { id: tokenId },
          relations: ['client'],
        });

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

        this.logger.debug('JTI validation passed', { jti: payload.jti });
      }

      this.logger.debug('OAuth2 token validation passed');
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
