import { Injectable, BadRequestException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from '../user/user.entity';
import { Client } from '../client/client.entity';

@Injectable()
export class OAuth2Service {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    @InjectRepository(Client)
    private readonly clientRepository: Repository<Client>,
  ) {}

  async getUserInfo(userId: string): Promise<User> {
    const user = await this.userRepository.findOne({
      where: { id: parseInt(userId) },
    });

    if (!user) {
      throw new BadRequestException('User not found');
    }

    return user;
  }

  private async validateClient(
    clientId: string,
    clientSecret?: string,
  ): Promise<Client> {
    const client = await this.clientRepository.findOne({
      where: { clientId, isActive: true },
    });

    if (!client) {
      throw new BadRequestException('Invalid client');
    }

    // Validate client secret if provided
    if (clientSecret && client.clientSecret !== clientSecret) {
      throw new BadRequestException('Invalid client credentials');
    }

    return client;
  }
}
