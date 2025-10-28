import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from '../auth/user.entity';
import { ProfileController } from './profile.controller';
import { ProfileService } from './profile.service';
import { AuthModule } from '../auth/auth.module';
import { CacheConfigModule } from '../cache/cache-config.module';
import { CommonModule } from '../common/common.module';
import { CacheManagerService } from '../dashboard/cache-manager.service';

@Module({
  imports: [
    TypeOrmModule.forFeature([User]),
    AuthModule,
    CacheConfigModule,
    CommonModule,
  ],
  controllers: [ProfileController],
  providers: [ProfileService, CacheManagerService],
  exports: [ProfileService],
})
export class ProfileModule {}
