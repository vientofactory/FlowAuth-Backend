import { Module } from '@nestjs/common';
import { RecaptchaService } from './recaptcha.util';
import { AppConfigService } from '../config/app-config.service';

@Module({
  providers: [RecaptchaService, AppConfigService],
  exports: [RecaptchaService],
})
export class UtilsModule {}
