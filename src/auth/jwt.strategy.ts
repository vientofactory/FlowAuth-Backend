import { Injectable, UnauthorizedException, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Strategy, ExtractJwt, StrategyOptions } from 'passport-jwt';
import { User } from '../user/user.entity';
import { Token } from '../token/token.entity';
import { AUTH_ERROR_MESSAGES, TOKEN_TYPES } from '../constants/auth.constants';
import { JwtPayload } from '../types/auth.types';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  private readonly logger = new Logger(JwtStrategy.name);
  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
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

  async validate(payload: JwtPayload): Promise<User> {
    try {
      this.logger.log('Validating token payload:', {
        sub: payload.sub,
        email: payload.email,
        type: payload.type,
      });

      // Validate payload structure
      if (!payload.sub || typeof payload.sub !== 'string') {
        this.logger.error('Invalid sub in payload');
        throw new UnauthorizedException(AUTH_ERROR_MESSAGES.INVALID_TOKEN);
      }

      if (!payload.email || typeof payload.email !== 'string') {
        this.logger.error('Invalid email in payload');
        throw new UnauthorizedException(AUTH_ERROR_MESSAGES.INVALID_TOKEN);
      }

      // Check token type - only login tokens are allowed here
      if (payload.type !== TOKEN_TYPES.LOGIN) {
        this.logger.error(`Invalid token type: ${payload.type}`);
        throw new UnauthorizedException(AUTH_ERROR_MESSAGES.INVALID_TOKEN_TYPE);
      }

      // If jti is present, verify token exists in database (for revocation check)
      if (payload.jti) {
        // Validate that jti is a valid numeric string
        if (typeof payload.jti !== 'string' || isNaN(Number(payload.jti))) {
          throw new UnauthorizedException(AUTH_ERROR_MESSAGES.INVALID_TOKEN);
        }

        const tokenId = parseInt(payload.jti, 10);
        const token = await this.tokenRepository.findOne({
          where: { id: tokenId },
          relations: ['user'],
        });

        if (!token) {
          throw new UnauthorizedException(AUTH_ERROR_MESSAGES.INVALID_TOKEN);
        }

        if (!token.user) {
          throw new UnauthorizedException(AUTH_ERROR_MESSAGES.INVALID_TOKEN);
        }

        // Verify token belongs to the user
        if (token.user.id !== parseInt(payload.sub, 10)) {
          throw new UnauthorizedException(AUTH_ERROR_MESSAGES.INVALID_TOKEN);
        }

        // Verify token is not revoked and not expired
        if (token.isRevoked || token.expiresAt < new Date()) {
          throw new UnauthorizedException(AUTH_ERROR_MESSAGES.INVALID_TOKEN);
        }
      }

      // Find user in database
      this.logger.log(
        `Looking up user in database for id: ${parseInt(payload.sub)}`,
      );
      const user = await this.userRepository.findOne({
        where: { id: parseInt(payload.sub) },
        select: [
          'id',
          'email',
          'username',
          'firstName',
          'lastName',
          'permissions',
          'avatar',
        ],
      });

      if (!user) {
        this.logger.error(`User not found for id: ${parseInt(payload.sub)}`);
        throw new UnauthorizedException(AUTH_ERROR_MESSAGES.USER_NOT_FOUND);
      }

      this.logger.log('User found:', {
        id: user.id,
        email: user.email,
        hasAvatar: !!user.avatar,
      });

      // Verify email matches
      if (user.email !== payload.email) {
        throw new UnauthorizedException(AUTH_ERROR_MESSAGES.INVALID_TOKEN);
      }

      return user;
    } catch (error: unknown) {
      if (error instanceof UnauthorizedException) {
        throw error;
      }

      throw new UnauthorizedException(AUTH_ERROR_MESSAGES.INVALID_TOKEN);
    }
  }
}
