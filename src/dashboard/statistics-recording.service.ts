import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import {
  TokenStatistics,
  ScopeStatistics,
  ClientStatistics,
  TokenEventType,
  ScopeEventType,
} from './statistics.entity';

@Injectable()
export class StatisticsRecordingService {
  private readonly logger = new Logger(StatisticsRecordingService.name);

  constructor(
    @InjectRepository(TokenStatistics)
    private tokenStatisticsRepository: Repository<TokenStatistics>,
    @InjectRepository(ScopeStatistics)
    private scopeStatisticsRepository: Repository<ScopeStatistics>,
    @InjectRepository(ClientStatistics)
    private clientStatisticsRepository: Repository<ClientStatistics>,
  ) {}

  /**
   * 토큰 발급 이벤트 기록
   */
  async recordTokenIssued(
    userId: number,
    clientId: number | null,
    scopes: string[],
    eventDate: Date = new Date(),
  ): Promise<void> {
    try {
      const eventDateOnly = new Date(eventDate.toISOString().split('T')[0]);

      // 토큰 발급 이벤트 기록
      const tokenStatData: Partial<TokenStatistics> = {
        userId,
        eventType: TokenEventType.ISSUED,
        eventDate: eventDateOnly,
        count: 1,
      };

      if (clientId !== null) {
        tokenStatData.clientId = clientId;
      }

      await this.tokenStatisticsRepository.upsert(tokenStatData, {
        conflictPaths: ['userId', 'clientId', 'eventType', 'eventDate'],
        skipUpdateIfNoValuesChanged: false,
      });

      // 스코프별 이벤트 기록
      for (const scope of scopes) {
        await this.scopeStatisticsRepository.upsert(
          {
            userId,
            scope,
            eventType: ScopeEventType.GRANTED,
            eventDate: eventDateOnly,
            count: 1,
          },
          {
            conflictPaths: ['userId', 'scope', 'eventType', 'eventDate'],
            skipUpdateIfNoValuesChanged: false,
          },
        );
      }

      // 클라이언트 통계 업데이트
      if (clientId) {
        await this.updateClientStatistics(userId, clientId, eventDateOnly, {
          tokensIssued: 1,
          tokensActive: 1,
        });
      }
    } catch (error) {
      this.logger.error('Failed to record token issued event:', error);
      // 통계 기록 실패는 메인 로직에 영향을 주지 않도록 함
    }
  }

  /**
   * 토큰 취소 이벤트 기록
   */
  async recordTokenRevoked(
    userId: number,
    clientId: number | null,
    scopes: string[],
    revokedReason: string | null = null,
    eventDate: Date = new Date(),
  ): Promise<void> {
    try {
      const eventDateOnly = new Date(eventDate.toISOString().split('T')[0]);

      // 토큰 취소 이벤트 기록
      const revokeStatData: Partial<TokenStatistics> = {
        userId,
        eventType: TokenEventType.REVOKED,
        eventDate: eventDateOnly,
        count: 1,
      };

      if (clientId !== null) {
        revokeStatData.clientId = clientId;
      }

      if (revokedReason !== null) {
        revokeStatData.revokedReason = revokedReason;
      }

      await this.tokenStatisticsRepository.upsert(revokeStatData, {
        conflictPaths: ['userId', 'clientId', 'eventType', 'eventDate'],
        skipUpdateIfNoValuesChanged: false,
      });

      // 스코프 취소 이벤트 기록
      for (const scope of scopes) {
        await this.scopeStatisticsRepository.upsert(
          {
            userId,
            scope,
            eventType: ScopeEventType.REVOKED,
            eventDate: eventDateOnly,
            count: 1,
          },
          {
            conflictPaths: ['userId', 'scope', 'eventType', 'eventDate'],
            skipUpdateIfNoValuesChanged: false,
          },
        );
      }

      // 클라이언트 통계 업데이트
      if (clientId) {
        await this.updateClientStatistics(userId, clientId, eventDateOnly, {
          tokensRevoked: 1,
          tokensActive: -1, // 활성 토큰 감소
        });
      }
    } catch (error) {
      this.logger.error('Failed to record token revoked event:', error);
    }
  }

  /**
   * 토큰 만료 이벤트 기록
   */
  async recordTokenExpired(
    userId: number,
    clientId: number | null,
    scopes: string[],
    eventDate: Date = new Date(),
  ): Promise<void> {
    try {
      const eventDateOnly = new Date(eventDate.toISOString().split('T')[0]);

      // 토큰 만료 이벤트 기록
      const expireStatData: Partial<TokenStatistics> = {
        userId,
        eventType: TokenEventType.EXPIRED,
        eventDate: eventDateOnly,
        count: 1,
      };

      if (clientId !== null) {
        expireStatData.clientId = clientId;
      }

      await this.tokenStatisticsRepository.upsert(expireStatData, {
        conflictPaths: ['userId', 'clientId', 'eventType', 'eventDate'],
        skipUpdateIfNoValuesChanged: false,
      });

      // 클라이언트 통계 업데이트
      if (clientId) {
        await this.updateClientStatistics(userId, clientId, eventDateOnly, {
          tokensExpired: 1,
          tokensActive: -1, // 활성 토큰 감소
        });
      }
    } catch (error) {
      this.logger.error('Failed to record token expired event:', error);
    }
  }

  /**
   * 클라이언트 통계 업데이트 헬퍼 메서드
   */
  private async updateClientStatistics(
    userId: number,
    clientId: number,
    eventDate: Date,
    updates: {
      tokensIssued?: number;
      tokensActive?: number;
      tokensExpired?: number;
      tokensRevoked?: number;
    },
  ): Promise<void> {
    try {
      // 기존 통계 조회 또는 생성
      let clientStat = await this.clientStatisticsRepository.findOne({
        where: {
          userId,
          clientId,
          eventDate,
        },
      });

      if (!clientStat) {
        // 클라이언트 이름 조회 (간단하게 하드코딩하거나 파라미터로 받을 수 있음)
        const clientName = `Client ${clientId}`; // 실제로는 Client 엔티티에서 조회 필요
        clientStat = this.clientStatisticsRepository.create({
          userId,
          clientId,
          clientName,
          eventDate,
          tokensIssued: 0,
          tokensActive: 0,
          tokensExpired: 0,
          tokensRevoked: 0,
        });
      }

      // 값 업데이트
      if (updates.tokensIssued !== undefined) {
        clientStat.tokensIssued += updates.tokensIssued;
      }
      if (updates.tokensActive !== undefined) {
        clientStat.tokensActive += updates.tokensActive;
      }
      if (updates.tokensExpired !== undefined) {
        clientStat.tokensExpired += updates.tokensExpired;
      }
      if (updates.tokensRevoked !== undefined) {
        clientStat.tokensRevoked += updates.tokensRevoked;
      }

      await this.clientStatisticsRepository.save(clientStat);
    } catch (error) {
      this.logger.error('Failed to update client statistics:', error);
    }
  }

  /**
   * 기존 토큰 데이터를 통계 테이블로 마이그레이션
   * (초기 데이터 구축용)
   */
  migrateExistingTokenData(): void {
    this.logger.log(
      'Starting migration of existing token data to statistics tables...',
    );
    // 이 메서드는 별도 구현 필요 - 기존 토큰 데이터를 분석하여 통계로 변환
    // 복잡한 로직이므로 별도 작업으로 분리
  }
}
