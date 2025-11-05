import { Injectable, BadRequestException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from '../auth/user.entity';

@Injectable()
export class OAuth2Service {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
  ) {}

  /**
   * Convert database tinyint values (0/1) to proper boolean values
   */
  private convertUserBooleans(user: User): User {
    return {
      ...user,
      isEmailVerified: Boolean(user.isEmailVerified),
      isTwoFactorEnabled: Boolean(user.isTwoFactorEnabled),
      isActive: Boolean(user.isActive),
    };
  }

  async getUserInfo(userId: string): Promise<User> {
    const user = await this.userRepository.findOne({
      where: { id: parseInt(userId) },
    });

    if (!user) {
      throw new BadRequestException('User not found');
    }

    return this.convertUserBooleans(user);
  }
}
