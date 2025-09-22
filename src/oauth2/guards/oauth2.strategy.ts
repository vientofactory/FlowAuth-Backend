import { Injectable, UnauthorizedException } from '@nestjs/common';
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
      console.log('OAuth2Strategy: Validating OAuth2 token payload:', {
        sub: payload.sub,
        client_id: payload.client_id,
        scopes: payload.scopes,
        token_type: payload.token_type,
        hasJti: !!payload.jti,
      });

      // Validate OAuth2 payload structure
      if (payload.token_type !== 'Bearer') {
        console.log('OAuth2Strategy: Invalid token_type:', payload.token_type);
        throw new UnauthorizedException(AUTH_ERROR_MESSAGES.INVALID_TOKEN);
      }

      if (!Array.isArray(payload.scopes)) {
        console.log('OAuth2Strategy: Invalid scopes format');
        throw new UnauthorizedException(AUTH_ERROR_MESSAGES.INVALID_TOKEN);
      }

      // If jti is present, verify token exists in database (for revocation check)
      if (payload.jti) {
        console.log('OAuth2Strategy: Checking jti:', payload.jti);
        const tokenId = parseInt(payload.jti, 10);
        const token = await this.tokenRepository.findOne({
          where: { id: tokenId },
          relations: ['client'],
        });

        if (!token) {
          console.log('OAuth2Strategy: Token not found in database');
          throw new UnauthorizedException(AUTH_ERROR_MESSAGES.INVALID_TOKEN);
        }

        if (!token.client) {
          console.log('OAuth2Strategy: Token has no associated client');
          throw new UnauthorizedException(AUTH_ERROR_MESSAGES.INVALID_TOKEN);
        }

        // Verify token belongs to the client
        if (payload.client_id && token.client.clientId !== payload.client_id) {
          console.log('OAuth2Strategy: Token client mismatch');
          throw new UnauthorizedException(AUTH_ERROR_MESSAGES.INVALID_TOKEN);
        }

        // Verify token is not revoked and not expired
        if (token.isRevoked || token.expiresAt < new Date()) {
          console.log('OAuth2Strategy: Token is revoked or expired');
          throw new UnauthorizedException(AUTH_ERROR_MESSAGES.INVALID_TOKEN);
        }

        console.log('OAuth2Strategy: JTI validation passed');
      }

      console.log('OAuth2Strategy: OAuth2 token validation passed');
      return payload;
    } catch (error: unknown) {
      if (error instanceof UnauthorizedException) {
        throw error;
      }

      console.log('OAuth2Strategy: Unexpected error during validation:', error);
      throw new UnauthorizedException(AUTH_ERROR_MESSAGES.INVALID_TOKEN);
    }
  }
}
