import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Client } from '../client/client.entity';
import { User } from '../user/user.entity';
import { TokenService } from '../oauth2/token.service';
import { DashboardStatsResponseDto } from './dto/dashboard-stats.dto';

@Injectable()
export class DashboardService {
  constructor(
    @InjectRepository(Client)
    private clientRepository: Repository<Client>,
    @InjectRepository(User)
    private userRepository: Repository<User>,
    private tokenService: TokenService,
  ) {}

  async getDashboardStats(userId: number): Promise<DashboardStatsResponseDto> {
    // Get total clients count for this user
    const totalClients = await this.getTotalClientsCount(userId);

    // Get active tokens count for this user
    const activeTokens = await this.getActiveTokensCount(userId);

    // Get user info for account creation date
    const user = await this.userRepository.findOne({
      where: { id: userId },
      select: ['createdAt'],
    });

    return {
      totalClients,
      activeTokens,
      lastLoginDate: null, // TODO: Add lastLoginAt field to User entity
      accountCreated: user?.createdAt || null,
    };
  }

  private async getTotalClientsCount(userId: number): Promise<number> {
    return await this.clientRepository.count({
      where: { isActive: true, userId },
    });
  }

  private async getActiveTokensCount(userId: number): Promise<number> {
    return await this.tokenService.getActiveTokensCountForUser(userId);
  }
}
