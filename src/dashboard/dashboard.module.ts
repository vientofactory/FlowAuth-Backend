import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Client } from '../client/client.entity';
import { User } from '../user/user.entity';
import { Token } from '../token/token.entity';
import { OAuth2Module } from '../oauth2/oauth2.module';
import { DashboardController } from './dashboard.controller';
import { DashboardService } from './dashboard.service';
import { LoggingModule } from '../logging/logging.module';

@Module({
  imports: [
    TypeOrmModule.forFeature([Client, User, Token]),
    OAuth2Module,
    LoggingModule,
  ],
  controllers: [DashboardController],
  providers: [DashboardService],
  exports: [DashboardService],
})
export class DashboardModule {}
