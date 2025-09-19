import { Injectable } from '@nestjs/common';
import { GeneralSettingsDto } from './dto/general-settings.dto';
import { SecuritySettingsDto } from './dto/security-settings.dto';
import { NotificationSettingsDto } from './dto/notification-settings.dto';

@Injectable()
export class SettingsService {
  // 임시 저장소 - 실제로는 데이터베이스나 설정 파일을 사용해야 함
  private generalSettings: GeneralSettingsDto = {
    siteName: 'FlowAuth',
    siteDescription: 'OAuth2 인증 시스템',
    adminEmail: 'admin@flowauth.com',
    defaultTokenExpiry: 86400,
    defaultRefreshTokenExpiry: 86400 * 30,
  };

  private securitySettings: SecuritySettingsDto = {
    enableTwoFactor: false,
    requireStrongPasswords: true,
    enableLoginNotifications: true,
    sessionTimeout: 1800,
    maxLoginAttempts: 5,
    enableAuditLog: true,
  };

  private notificationSettings: NotificationSettingsDto = {
    emailNotifications: true,
    newClientNotifications: true,
    tokenExpiryNotifications: true,
    securityAlerts: true,
    systemUpdates: false,
  };

  // 일반 설정
  getGeneralSettings(): GeneralSettingsDto {
    return { ...this.generalSettings };
  }

  updateGeneralSettings(settings: GeneralSettingsDto): GeneralSettingsDto {
    this.generalSettings = { ...settings };
    return this.getGeneralSettings();
  }

  // 보안 설정
  getSecuritySettings(): SecuritySettingsDto {
    return { ...this.securitySettings };
  }

  updateSecuritySettings(settings: SecuritySettingsDto): SecuritySettingsDto {
    this.securitySettings = { ...settings };
    return this.getSecuritySettings();
  }

  // 알림 설정
  getNotificationSettings(): NotificationSettingsDto {
    return { ...this.notificationSettings };
  }

  updateNotificationSettings(
    settings: NotificationSettingsDto,
  ): NotificationSettingsDto {
    this.notificationSettings = { ...settings };
    return this.getNotificationSettings();
  }

  // 모든 설정 가져오기
  getAllSettings() {
    return {
      general: this.getGeneralSettings(),
      security: this.getSecuritySettings(),
      notification: this.getNotificationSettings(),
    };
  }

  // 설정 데이터 내보내기
  exportSettings() {
    return {
      exportedAt: new Date().toISOString(),
      version: '1.0',
      data: this.getAllSettings(),
    };
  }

  // 설정 데이터 가져오기
  importSettings(data: {
    general: GeneralSettingsDto;
    security: SecuritySettingsDto;
    notification: NotificationSettingsDto;
  }) {
    this.generalSettings = { ...data.general };
    this.securitySettings = { ...data.security };
    this.notificationSettings = { ...data.notification };

    return {
      importedAt: new Date().toISOString(),
      message: '설정이 성공적으로 가져와졌습니다.',
      data: this.getAllSettings(),
    };
  }
}
