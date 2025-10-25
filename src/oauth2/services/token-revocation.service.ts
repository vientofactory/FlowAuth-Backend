import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, LessThan } from 'typeorm';
import { Token } from '../token.entity';
import { AuditLogService } from '../../common/audit-log.service';
import { AuditEventType, AuditSeverity } from '../../common/audit-log.entity';

@Injectable()
export class TokenRevocationService {
  constructor(
    @InjectRepository(Token)
    private tokenRepository: Repository<Token>,
    private auditLogService: AuditLogService,
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
            resourceType: 'token',
            metadata: {
              tokenId: token.id,
              clientName: token.client?.name,
              scopes: token.scopes,
              reason: 'user_revoked',
            },
          });
        } catch (error) {
          // 감사 로그 기록 실패해도 토큰 취소는 계속 진행
          console.error(
            'Failed to create audit log for token revocation:',
            error,
          );
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
