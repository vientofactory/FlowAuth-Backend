import { Controller, Get, Put, Post, Body, UseGuards } from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
} from '@nestjs/swagger';
import { SettingsService } from './settings.service';
import { GeneralSettingsDto } from './dto/general-settings.dto';
import { SecuritySettingsDto } from './dto/security-settings.dto';
import { NotificationSettingsDto } from './dto/notification-settings.dto';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';

@Controller('settings')
@ApiTags('Settings')
export class SettingsController {
  constructor(private readonly settingsService: SettingsService) {}

  @Get('general')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({
    summary: '일반 설정 조회',
    description: '시스템의 일반 설정 정보를 조회합니다.',
  })
  @ApiResponse({
    status: 200,
    description: '일반 설정 정보',
    type: GeneralSettingsDto,
  })
  getGeneralSettings(): GeneralSettingsDto {
    return this.settingsService.getGeneralSettings();
  }

  @Put('general')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({
    summary: '일반 설정 업데이트',
    description: '시스템의 일반 설정을 업데이트합니다.',
  })
  @ApiResponse({
    status: 200,
    description: '업데이트된 일반 설정',
    type: GeneralSettingsDto,
  })
  updateGeneralSettings(
    @Body() settings: GeneralSettingsDto,
  ): GeneralSettingsDto {
    return this.settingsService.updateGeneralSettings(settings);
  }

  @Get('security')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({
    summary: '보안 설정 조회',
    description: '시스템의 보안 설정 정보를 조회합니다.',
  })
  @ApiResponse({
    status: 200,
    description: '보안 설정 정보',
    type: SecuritySettingsDto,
  })
  getSecuritySettings(): SecuritySettingsDto {
    return this.settingsService.getSecuritySettings();
  }

  @Put('security')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({
    summary: '보안 설정 업데이트',
    description: '시스템의 보안 설정을 업데이트합니다.',
  })
  @ApiResponse({
    status: 200,
    description: '업데이트된 보안 설정',
    type: SecuritySettingsDto,
  })
  updateSecuritySettings(
    @Body() settings: SecuritySettingsDto,
  ): SecuritySettingsDto {
    return this.settingsService.updateSecuritySettings(settings);
  }

  @Get('notifications')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({
    summary: '알림 설정 조회',
    description: '시스템의 알림 설정 정보를 조회합니다.',
  })
  @ApiResponse({
    status: 200,
    description: '알림 설정 정보',
    type: NotificationSettingsDto,
  })
  getNotificationSettings(): NotificationSettingsDto {
    return this.settingsService.getNotificationSettings();
  }

  @Put('notifications')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({
    summary: '알림 설정 업데이트',
    description: '시스템의 알림 설정을 업데이트합니다.',
  })
  @ApiResponse({
    status: 200,
    description: '업데이트된 알림 설정',
    type: NotificationSettingsDto,
  })
  updateNotificationSettings(
    @Body() settings: NotificationSettingsDto,
  ): NotificationSettingsDto {
    return this.settingsService.updateNotificationSettings(settings);
  }

  @Get()
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({
    summary: '모든 설정 조회',
    description: '시스템의 모든 설정 정보를 조회합니다.',
  })
  @ApiResponse({
    status: 200,
    description: '모든 설정 정보',
  })
  getAllSettings() {
    return this.settingsService.getAllSettings();
  }

  @Get('export')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({
    summary: '설정 데이터 내보내기',
    description: '시스템 설정 데이터를 JSON 형식으로 내보냅니다.',
  })
  @ApiResponse({
    status: 200,
    description: '설정 데이터',
  })
  exportSettings() {
    return this.settingsService.exportSettings();
  }

  @Post('import')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({
    summary: '설정 데이터 가져오기',
    description: 'JSON 형식의 설정 데이터를 가져와서 적용합니다.',
  })
  @ApiResponse({
    status: 200,
    description: '설정 데이터가 성공적으로 적용됨',
  })
  importSettings(
    @Body()
    data: {
      general: GeneralSettingsDto;
      security: SecuritySettingsDto;
      notification: NotificationSettingsDto;
    },
  ) {
    return this.settingsService.importSettings(data);
  }
}
