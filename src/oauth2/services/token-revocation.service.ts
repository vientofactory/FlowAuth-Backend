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
    const token = await this.tokenRepository.findOne({
      where: { accessToken },
      relations: ['user', 'client'],
    });

    if (token) {
      token.isRevoked = true;
      token.revokedAt = new Date();
      await this.tokenRepository.save(token);

      // 토큰 취소 시 캐시 무효화
      await this.cacheManagerService.delCacheKey(
        CACHE_KEYS.oauth2.token(accessToken),
      );

      // 감사 로그 기록
      if (token.user) {
        try {
          await this.auditLogService.create({
            eventType: AuditEventType.TOKEN_REVOKED,
            severity: AuditSeverity.MEDIUM,
            description: `토큰이 취소되었습니다. 클라이언트: ${token.client?.name ?? 'Unknown'}`,
            userId: token.user.id,
            clientId: token.client?.id,
            resourceId: token.id,
            resourceType: AUDIT_LOG_RESOURCE_TYPES.TOKEN,
            metadata: {
              tokenId: token.id,
              clientName: token.client?.name,
              scopes: token.scopes,
              reason: 'user_revoked',
            },
          });
        } catch {
          // 감사 로그 기록 실패해도 토큰 취소는 계속 진행
        }
      }
    }
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
    const tokens = await this.tokenRepository.find({
      where: { user: { id: userId }, isRevoked: false },
    });

    const now = new Date();
    for (const token of tokens) {
      token.isRevoked = true;
      token.revokedAt = now;
    }

    await this.tokenRepository.save(tokens);

    // 사용자 토큰 취소 시 관련 캐시 무효화
    for (const token of tokens) {
      if (token.accessToken) {
        await this.cacheManagerService.delCacheKey(
          CACHE_KEYS.oauth2.token(token.accessToken),
        );
      }
    }
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
      expiresAt: LessThan(now),
    });
    return result.affected ?? 0;
  }
}
