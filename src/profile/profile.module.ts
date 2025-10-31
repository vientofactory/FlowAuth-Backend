import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ProfileController } from './profile.controller';
import { ProfileService } from './profile.service';
import { AuthModule } from '../auth/auth.module';
import { CacheConfigModule } from '../cache/cache-config.module';
import { CommonModule } from '../common/common.module';
import { AUTH_ENTITIES } from '../database/database.module';

@Module({
  imports: [
    TypeOrmModule.forFeature(AUTH_ENTITIES),
    AuthModule,
    CacheConfigModule,
    CommonModule,
  ],
  controllers: [ProfileController],
  providers: [ProfileService],
  exports: [ProfileService],
})
export class ProfileModule {}
