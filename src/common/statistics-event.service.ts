import { Injectable, Logger } from '@nestjs/common';
import { ModuleRef } from '@nestjs/core';
import { StatisticsRecordingService } from '../dashboard/statistics-recording.service';

@Injectable()
export class StatisticsEventService {
  private readonly logger = new Logger(StatisticsEventService.name);
  private statisticsRecordingService: StatisticsRecordingService | null = null;

  constructor(private moduleRef: ModuleRef) {}

  /**
   * Lazy load StatisticsRecordingService instance
   */
  private async getStatisticsRecordingService(): Promise<StatisticsRecordingService> {
    if (!this.statisticsRecordingService) {
      try {
        this.statisticsRecordingService = await this.moduleRef.get(
          StatisticsRecordingService,
          { strict: false },
        );
      } catch (error) {
        this.logger.warn('StatisticsRecordingService not available:', error);
        throw error;
      }
    }
    return this.statisticsRecordingService!;
  }

  /**
   * Record token issued event
   */
  async recordTokenIssued(
    userId: number,
    clientId: number | null,
    scopes: string[],
    eventDate: Date = new Date(),
  ): Promise<void> {
    try {
      const service = await this.getStatisticsRecordingService();
      await service.recordTokenIssued(userId, clientId, scopes, eventDate);
    } catch (error) {
      this.logger.warn('Failed to record token issued event:', error);
    }
  }

  /**
   * Record token revoked event
   */
  async recordTokenRevoked(
    userId: number,
    clientId: number | null,
    scopes: string[],
    revokedReason: string | null = null,
    eventDate: Date = new Date(),
  ): Promise<void> {
    try {
      const service = await this.getStatisticsRecordingService();
      await service.recordTokenRevoked(
        userId,
        clientId,
        scopes,
        revokedReason,
        eventDate,
      );
    } catch (error) {
      this.logger.warn('Failed to record token revoked event:', error);
    }
  }

  /**
   * Record token expired event
   */
  async recordTokenExpired(
    userId: number,
    clientId: number | null,
    scopes: string[],
    eventDate: Date = new Date(),
  ): Promise<void> {
    try {
      const service = await this.getStatisticsRecordingService();
      await service.recordTokenExpired(userId, clientId, scopes, eventDate);
    } catch (error) {
      this.logger.warn('Failed to record token expired event:', error);
    }
  }
}
