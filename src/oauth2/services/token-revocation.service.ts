import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, LessThan } from 'typeorm';
import { Token } from '../token.entity';
import { AuditLogService } from '../../common/audit-log.service';
import { AuditEventType, AuditSeverity } from '../../common/audit-log.entity';
import { CACHE_KEYS } from '../../constants/cache.constants';
import { AUDIT_LOG_RESOURCE_TYPES } from '../../constants/oauth2.constants';
import { CacheManagerService } from '../../cache/cache-manager.service';

@Injectable()
export class TokenRevocationService {
  constructor(
    @InjectRepository(Token)
    private tokenRepository: Repository<Token>,
    private auditLogService: AuditLogService,
    private cacheManagerService: CacheManagerService,
  ) {}

  async revokeToken(accessToken: string): Promise<void> {
    const dataSource = this.tokenRepository.manager.connection;

    await dataSource.transaction(async (manager) => {
      const token = await manager.findOne(Token, {
        where: { accessToken },
        relations: ['user', 'client'],
        lock: { mode: 'pessimistic_write' },
      });

      if (token) {
        // Update token status within transaction
        await manager.getRepository(Token).update(token.id, {
          isRevoked: true,
          revokedAt: new Date(),
        });

        // 토큰 취소 시 캐시 무효화 (after successful DB update)
        await this.cacheManagerService.delCacheKey(
          CACHE_KEYS.oauth2.token(accessToken),
        );

        // 감사 로그 기록 (비동기로 처리하여 트랜잭션 성능에 영향 없이)
        if (token.user) {
          const userId = token.user.id;
          const clientId = token.client?.id;
          const clientName = token.client?.name;

          setImmediate(() => {
            this.auditLogService
              .create({
                eventType: AuditEventType.TOKEN_REVOKED,
                severity: AuditSeverity.MEDIUM,
                description: `토큰이 취소되었습니다. 클라이언트: ${clientName ?? 'Unknown'}`,
                userId,
                clientId,
                resourceId: token.id,
                resourceType: AUDIT_LOG_RESOURCE_TYPES.TOKEN,
                metadata: {
                  tokenId: token.id,
                  clientName,
                  scopes: token.scopes,
                  reason: 'user_revoked',
                },
              })
              .catch((auditError) => {
                // 감사 로그 기록 실패해도 토큰 취소는 이미 완료됨
                console.error('Audit log creation failed:', auditError);
              });
          });
        }
      }
    });
  }

  async revokeRefreshToken(refreshToken: string): Promise<void> {
    const token = await this.tokenRepository.findOne({
      where: { refreshToken },
    });

    if (token) {
      token.isRevoked = true;
      token.revokedAt = new Date();
      await this.tokenRepository.save(token);
    }
  }

  async revokeAllUserTokens(userId: number): Promise<void> {
    const dataSource = this.tokenRepository.manager.connection;

    await dataSource.transaction(async (manager) => {
      const tokens = await manager.find(Token, {
        where: { user: { id: userId }, isRevoked: false },
        lock: { mode: 'pessimistic_write' },
      });

      if (tokens.length === 0) {
        return;
      }

      const now = new Date();
      const tokenIds = tokens.map((token) => token.id);

      // Bulk update for better performance
      await manager.getRepository(Token).update(tokenIds, {
        isRevoked: true,
        revokedAt: now,
      });

      // 사용자 토큰 취소 시 관련 캐시 무효화 (after successful DB update)
      const cachePromises = tokens
        .filter((token) => token.accessToken)
        .map((token) =>
          this.cacheManagerService.delCacheKey(
            CACHE_KEYS.oauth2.token(token.accessToken),
          ),
        );

      await Promise.all(cachePromises);
    });
  }

  async revokeAllClientTokens(clientId: string): Promise<void> {
    const tokens = await this.tokenRepository.find({
      where: { client: { clientId }, isRevoked: false },
    });

    const now = new Date();
    for (const token of tokens) {
      token.isRevoked = true;
      token.revokedAt = now;
    }

    await this.tokenRepository.save(tokens);
  }

  async cleanupExpiredTokens(): Promise<number> {
    const now = new Date();
    const result = await this.tokenRepository.delete({
      refreshExpiresAt: LessThan(now),
    });
    return result.affected ?? 0;
  }
}
