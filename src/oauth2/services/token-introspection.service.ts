import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { TokenService } from '../token.service';
import { OAuth2Service } from '../oauth2.service';
import { Token } from '../token.entity';
import { Client } from '../client.entity';
import { StructuredLogger } from '../../logging/structured-logger.service';
import { TOKEN_INTROSPECTION_CONSTANTS } from '../../constants/jwt.constants';

export interface TokenIntrospectionResult {
  active: boolean;
  client_id?: string;
  exp?: number;
  iat?: number;
  sub?: string;
  scope?: string;
  token_type?: string;
  username?: string;
  email?: string;
  email_verified?: boolean;
}

@Injectable()
export class TokenIntrospectionService {
  constructor(
    private readonly tokenService: TokenService,
    private readonly oauth2Service: OAuth2Service,
    @InjectRepository(Token)
    private readonly tokenRepository: Repository<Token>,
    @InjectRepository(Client)
    private readonly clientRepository: Repository<Client>,
    private readonly structuredLogger: StructuredLogger,
  ) {}

  /**
   * 토큰 타입 자동 판별
   */
  determineTokenType(token: string, hint?: string): string {
    // 힌트가 제공된 경우 우선 사용
    if (hint) {
      return hint;
    }

    // JWT 형식인 경우 헤더에서 타입 판별
    if (token.split('.').length === 3) {
      try {
        const payload = JSON.parse(
          Buffer.from(token.split('.')[1], 'base64url').toString(),
        ) as { nonce?: string; scopes?: string[]; scope?: string };

        // ID 토큰은 nonce 클레임이 있는 경우가 많음
        if (payload.nonce !== undefined) {
          return 'id_token';
        }

        // 액세스 토큰은 scopes가 있는 경우
        if (payload.scopes || payload.scope) {
          return 'access_token';
        }
      } catch {
        // 파싱 실패 시 기본값
      }
    }

    // 기본적으로 액세스 토큰으로 가정
    return 'access_token';
  }

  /**
   * ID 토큰 인트로스펙션
   */
  async introspectIdToken(
    token: string,
    expectedClientId?: string,
  ): Promise<TokenIntrospectionResult> {
    try {
      // 클라이언트 ID 검증을 위한 클라이언트 조회
      let clientId = expectedClientId;
      if (!clientId) {
        // 토큰에서 audience 추출하여 클라이언트 ID 결정
        const payload = JSON.parse(
          Buffer.from(token.split('.')[1], 'base64url').toString(),
        ) as { aud?: string };
        clientId = payload.aud;
      }

      if (!clientId) {
        throw new Error('Client ID not found in token or request');
      }

      // 클라이언트 존재 확인
      const client = await this.clientRepository.findOne({
        where: { clientId },
      });
      if (!client) {
        throw new Error('Invalid client');
      }

      // ID 토큰 검증 (RSA 서명 + 클레임 검증)
      const payload = await this.tokenService.validateIdToken(
        token,
        clientId,
        undefined,
      );

      return {
        active: true,
        client_id: payload.aud,
        exp: payload.exp,
        iat: payload.iat,
        sub: payload.sub,
        token_type: TOKEN_INTROSPECTION_CONSTANTS.TOKEN_TYPES.ID_TOKEN,
        username:
          payload[TOKEN_INTROSPECTION_CONSTANTS.CLAIMS.USERNAME] ||
          payload.name,
        email: payload.email,
        email_verified:
          payload[TOKEN_INTROSPECTION_CONSTANTS.CLAIMS.EMAIL_VERIFIED],
      };
    } catch (error) {
      this.structuredLogger.warn(
        {
          message: 'ID token introspection failed',
          error: error instanceof Error ? error.message : 'Unknown error',
        },
        'TokenIntrospectionService',
      );
      return { active: TOKEN_INTROSPECTION_CONSTANTS.TOKEN_STATUS.INACTIVE };
    }
  }

  /**
   * 액세스 토큰 인트로스펙션
   */
  async introspectAccessToken(
    token: string,
  ): Promise<TokenIntrospectionResult> {
    try {
      // 액세스 토큰 검증
      const payload = await this.tokenService.validateToken(token);

      if (!payload) {
        return { active: TOKEN_INTROSPECTION_CONSTANTS.TOKEN_STATUS.INACTIVE };
      }

      // 클라이언트 존재 확인
      const client = await this.clientRepository.findOne({
        where: { clientId: payload.client_id || '' },
      });
      if (!client) {
        return { active: TOKEN_INTROSPECTION_CONSTANTS.TOKEN_STATUS.INACTIVE };
      }

      return {
        active: true,
        client_id: payload.client_id || undefined,
        exp: payload.exp,
        iat: payload.iat,
        sub: payload.sub || undefined,
        scope: payload.scopes?.join(' '),
        token_type: TOKEN_INTROSPECTION_CONSTANTS.TOKEN_TYPES.ACCESS_TOKEN,
        username: payload.sub || undefined, // 사용자 ID를 username으로 사용
      };
    } catch (error) {
      this.structuredLogger.warn(
        {
          message: 'Access token introspection failed',
          error: error instanceof Error ? error.message : 'Unknown error',
        },
        'TokenIntrospectionService',
      );
      return { active: TOKEN_INTROSPECTION_CONSTANTS.TOKEN_STATUS.INACTIVE };
    }
  }

  /**
   * 리프레시 토큰 인트로스펙션
   */
  async introspectRefreshToken(
    token: string,
  ): Promise<TokenIntrospectionResult> {
    try {
      // 데이터베이스에서 리프레시 토큰 조회
      const tokenEntity = await this.tokenRepository.findOne({
        where: { refreshToken: token },
        relations: ['user', 'client'],
      });

      if (!tokenEntity || tokenEntity.isRevoked) {
        return { active: TOKEN_INTROSPECTION_CONSTANTS.TOKEN_STATUS.INACTIVE };
      }

      // 만료 확인
      const now = new Date();
      if (!tokenEntity.refreshExpiresAt || tokenEntity.refreshExpiresAt < now) {
        return { active: TOKEN_INTROSPECTION_CONSTANTS.TOKEN_STATUS.INACTIVE };
      }

      // 클라이언트 존재 확인
      if (!tokenEntity.client) {
        return { active: TOKEN_INTROSPECTION_CONSTANTS.TOKEN_STATUS.INACTIVE };
      }

      const client = await this.clientRepository.findOne({
        where: {
          clientId: tokenEntity.client.clientId,
        },
      });
      if (!client) {
        return { active: TOKEN_INTROSPECTION_CONSTANTS.TOKEN_STATUS.INACTIVE };
      }

      return {
        active: true,
        client_id: tokenEntity.client.clientId,
        exp: Math.floor(tokenEntity.refreshExpiresAt.getTime() / 1000),
        iat: Math.floor(tokenEntity.createdAt.getTime() / 1000),
        sub: tokenEntity.user?.id.toString(),
        scope: tokenEntity.scopes ? tokenEntity.scopes.join(' ') : '',
        token_type: TOKEN_INTROSPECTION_CONSTANTS.TOKEN_TYPES.REFRESH_TOKEN,
        username: tokenEntity.user?.username,
      };
    } catch (error) {
      this.structuredLogger.warn(
        {
          message: 'Refresh token introspection failed',
          error: error instanceof Error ? error.message : 'Unknown error',
        },
        'TokenIntrospectionService',
      );
      return { active: TOKEN_INTROSPECTION_CONSTANTS.TOKEN_STATUS.INACTIVE };
    }
  }

  /**
   * 범용 토큰 인트로스펙션
   */
  async introspectToken(
    token: string,
    tokenTypeHint?: string,
  ): Promise<TokenIntrospectionResult> {
    const tokenType = this.determineTokenType(token, tokenTypeHint);

    switch (tokenType) {
      case 'id_token':
        return await this.introspectIdToken(token);
      case 'access_token':
        return await this.introspectAccessToken(token);
      case 'refresh_token':
        return await this.introspectRefreshToken(token);
      default:
        return { active: TOKEN_INTROSPECTION_CONSTANTS.TOKEN_STATUS.INACTIVE };
    }
  }
}
