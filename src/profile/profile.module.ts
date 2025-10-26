import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from '../auth/user.entity';
import { ProfileController } from './profile.controller';
import { ProfileService } from './profile.service';
import { LoggingModule } from '../logging/logging.module';
import { AuthModule } from '../auth/auth.module';
import { CacheConfigModule } from '../cache/cache-config.module';

@Module({
  imports: [
    TypeOrmModule.forFeature([User]),
    LoggingModule,
    AuthModule,
    CacheConfigModule,
  ],
  controllers: [ProfileController],
  providers: [ProfileService],
  exports: [ProfileService],
})
export class ProfileModule {}
