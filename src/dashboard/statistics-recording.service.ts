import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Client } from '../oauth2/client.entity';
import { Token } from '../oauth2/token.entity';
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
    @InjectRepository(Client)
    private clientRepository: Repository<Client>,
    @InjectRepository(Token)
    private tokenRepository: Repository<Token>,
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
        // 실제 Client 엔티티에서 클라이언트 이름 조회
        const client = await this.clientRepository.findOne({
          where: { id: clientId },
          select: ['name'],
        });
        const clientName = client?.name ?? `Client ${clientId}`;
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
  async migrateExistingTokenData(): Promise<void> {
    this.logger.log(
      'Starting migration of existing token data to statistics tables...',
    );

    try {
      // 기존 토큰 데이터 조회
      const tokens = await this.tokenRepository.find({
        relations: ['user', 'client'],
        select: [
          'id',
          'scopes',
          'createdAt',
          'isRevoked',
          'revokedAt',
          'expiresAt',
          'user',
          'client',
        ],
      });

      this.logger.log(`Found ${tokens.length} tokens to migrate`);

      // 통계 데이터 타입 정의
      interface ClientStatData {
        tokensIssued: number;
        tokensActive: number;
        tokensRevoked: number;
        tokensExpired: number;
      }

      interface UserStatData {
        tokensIssued: number;
        tokensRevoked: number;
        tokensExpired: number;
        scopesGranted: Map<string, number>;
        clientStats: Map<number, ClientStatData>;
      }

      // 날짜별로 그룹화하여 통계 계산
      const statsByDate = new Map<string, Map<number, UserStatData>>();

      for (const token of tokens) {
        // 사용자 정보가 없는 토큰은 건너뜀
        if (!token.user?.id) continue;

        const eventDate = new Date(token.createdAt.toISOString().split('T')[0]);
        const dateKey = eventDate.toISOString().split('T')[0];
        const userId = token.user.id;

        if (!statsByDate.has(dateKey)) {
          statsByDate.set(dateKey, new Map());
        }

        const userStats = statsByDate.get(dateKey)!;
        if (!userStats.has(userId)) {
          userStats.set(userId, {
            tokensIssued: 0,
            tokensRevoked: 0,
            tokensExpired: 0,
            scopesGranted: new Map<string, number>(),
            clientStats: new Map<number, ClientStatData>(),
          });
        }

        const userStat = userStats.get(userId)!;

        // 토큰 발급 통계
        userStat.tokensIssued++;

        // 토큰 취소 통계
        if (token.isRevoked) {
          userStat.tokensRevoked++;
        }

        // 토큰 만료 통계 (현재 시간 기준으로 만료된 토큰)
        if (
          token.expiresAt &&
          new Date() > token.expiresAt &&
          !token.isRevoked
        ) {
          userStat.tokensExpired++;
        }

        // 스코프별 통계
        if (token.scopes) {
          for (const scope of token.scopes) {
            userStat.scopesGranted.set(
              scope,
              (userStat.scopesGranted.get(scope) ?? 0) + 1,
            );
          }
        }

        // 클라이언트별 통계
        if (token.client?.id) {
          if (!userStat.clientStats.has(token.client.id)) {
            userStat.clientStats.set(token.client.id, {
              tokensIssued: 0,
              tokensActive: 0,
              tokensRevoked: 0,
              tokensExpired: 0,
            });
          }

          const clientStat = userStat.clientStats.get(token.client.id)!;
          clientStat.tokensIssued++;

          if (token.isRevoked) {
            clientStat.tokensRevoked++;
          } else if (token.expiresAt && new Date() > token.expiresAt) {
            clientStat.tokensExpired++;
          } else {
            clientStat.tokensActive++;
          }
        }
      }

      // 통계 데이터를 데이터베이스에 저장
      for (const [dateStr, userStats] of statsByDate) {
        const eventDate = new Date(dateStr);

        for (const [userId, userStat] of userStats) {
          // 토큰 통계 저장
          await this.tokenStatisticsRepository.upsert(
            {
              userId,
              eventType: TokenEventType.ISSUED,
              eventDate,
              count: userStat.tokensIssued,
            },
            {
              conflictPaths: ['userId', 'eventType', 'eventDate'],
              skipUpdateIfNoValuesChanged: false,
            },
          );

          if (userStat.tokensRevoked > 0) {
            await this.tokenStatisticsRepository.upsert(
              {
                userId,
                eventType: TokenEventType.REVOKED,
                eventDate,
                count: userStat.tokensRevoked,
              },
              {
                conflictPaths: ['userId', 'eventType', 'eventDate'],
                skipUpdateIfNoValuesChanged: false,
              },
            );
          }

          if (userStat.tokensExpired > 0) {
            await this.tokenStatisticsRepository.upsert(
              {
                userId,
                eventType: TokenEventType.EXPIRED,
                eventDate,
                count: userStat.tokensExpired,
              },
              {
                conflictPaths: ['userId', 'eventType', 'eventDate'],
                skipUpdateIfNoValuesChanged: false,
              },
            );
          }

          // 스코프 통계 저장
          for (const [scope, count] of userStat.scopesGranted) {
            await this.scopeStatisticsRepository.upsert(
              {
                userId,
                scope,
                eventType: ScopeEventType.GRANTED,
                eventDate,
                count,
              },
              {
                conflictPaths: ['userId', 'scope', 'eventType', 'eventDate'],
                skipUpdateIfNoValuesChanged: false,
              },
            );
          }

          // 클라이언트 통계 저장
          for (const [clientId, clientStat] of userStat.clientStats) {
            const client = await this.clientRepository.findOne({
              where: { id: clientId },
              select: ['name'],
            });
            const clientName = client?.name ?? `Client ${clientId}`;

            await this.clientStatisticsRepository.upsert(
              {
                userId,
                clientId,
                clientName,
                eventDate,
                tokensIssued: clientStat.tokensIssued,
                tokensActive: clientStat.tokensActive,
                tokensExpired: clientStat.tokensExpired,
                tokensRevoked: clientStat.tokensRevoked,
              },
              {
                conflictPaths: ['userId', 'clientId', 'eventDate'],
                skipUpdateIfNoValuesChanged: false,
              },
            );
          }
        }
      }

      this.logger.log('Migration completed successfully');
    } catch (error) {
      this.logger.error('Failed to migrate existing token data:', error);
      throw error;
    }
  }
}
