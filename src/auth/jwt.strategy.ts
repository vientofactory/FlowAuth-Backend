import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Strategy, ExtractJwt, StrategyOptions } from 'passport-jwt';
import { User } from '../user/user.entity';
import {
  JWT_CONSTANTS,
  AUTH_ERROR_MESSAGES,
} from '../constants/auth.constants';
import { JwtPayload } from '../types/auth.types';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
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
      // Validate payload structure
      if (!payload.sub || typeof payload.sub !== 'string') {
        throw new UnauthorizedException(AUTH_ERROR_MESSAGES.INVALID_TOKEN);
      }

      if (!payload.email || typeof payload.email !== 'string') {
        throw new UnauthorizedException(AUTH_ERROR_MESSAGES.INVALID_TOKEN);
      }

      // Check token type if specified
      if (payload.type !== JWT_CONSTANTS.TOKEN_TYPE) {
        throw new UnauthorizedException(AUTH_ERROR_MESSAGES.INVALID_TOKEN_TYPE);
      }

      // Find user in database
      const user = await this.userRepository.findOne({
        where: { id: parseInt(payload.sub) },
        select: [
          'id',
          'email',
          'username',
          'firstName',
          'lastName',
          'roles',
          'createdAt',
          'updatedAt',
        ],
      });

      if (!user) {
        throw new UnauthorizedException(AUTH_ERROR_MESSAGES.USER_NOT_FOUND);
      }

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
