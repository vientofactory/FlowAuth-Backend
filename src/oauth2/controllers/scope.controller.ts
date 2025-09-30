import {
  Controller,
  Get,
  Post,
  Request,
  BadRequestException,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { UseGuards } from '@nestjs/common';
import type { Request as ExpressRequest } from 'express';
import { JwtAuthGuard } from '../../auth/jwt-auth.guard';
import {
  PermissionsGuard,
  RequirePermissions,
} from '../../auth/permissions.guard';
import { PERMISSIONS, TOKEN_TYPES } from '../../constants/auth.constants';
import { OAuth2Service } from '../oauth2.service';
import { ScopeService } from '../scope.service';
import { JwtService } from '@nestjs/jwt';
import { TokenUtils } from '../../utils/permission.util';
import { PermissionUtils } from '../../utils/permission.util';

@Controller('oauth2')
@ApiTags('OAuth2 Scopes')
export class ScopeController {
  constructor(
    private readonly oauth2Service: OAuth2Service,
    private readonly scopeService: ScopeService,
    private readonly jwtService: JwtService,
  ) {}

  @Get('scopes')
  @ApiOperation({
    summary: '사용 가능한 스코프 목록 조회',
    description: `
시스템에 정의된 모든 OAuth2 스코프의 목록을 조회합니다.

**용도:**
- 클라이언트 개발자가 사용 가능한 스코프 확인
- OAuth2 테스터에서 동적 스코프 선택
    `,
  })
  @ApiResponse({
    status: 200,
    description: '스코프 목록과 메타 정보',
    schema: {
      type: 'object',
      properties: {
        scopes: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              name: {
                type: 'string',
                description: '스코프 이름',
                example: 'identify',
              },
              description: {
                type: 'string',
                description: '스코프 설명',
                example: '계정의 기본 정보 읽기 (사용자 ID, 이름 등)',
              },
              isDefault: {
                type: 'boolean',
                description: '기본 스코프 여부',
                example: false,
              },
            },
          },
        },
        meta: {
          type: 'object',
          properties: {
            total: {
              type: 'number',
              description: '전체 스코프 수',
              example: 19,
            },
            cached: {
              type: 'boolean',
              description: '캐시 사용 여부',
              example: true,
            },
            cacheSize: {
              type: 'number',
              description: '캐시에 저장된 스코프 수',
              example: 19,
            },
          },
        },
      },
    },
  })
  async getAvailableScopes() {
    const scopes = await this.scopeService.findAll();
    const cacheInfo = this.scopeService.getCacheInfo();

    return {
      scopes: scopes.map((scope) => ({
        name: scope.name,
        description: scope.description,
        isDefault: scope.isDefault,
      })),
      meta: {
        total: scopes.length,
        cached: cacheInfo.initialized,
        cacheSize: cacheInfo.cacheSize,
      },
    };
  }

  @Post('scopes/refresh')
  @UseGuards(JwtAuthGuard, PermissionsGuard)
  @RequirePermissions(PERMISSIONS.MANAGE_SYSTEM)
  async refreshScopesCache(@Request() req: ExpressRequest) {
    // JWT 토큰에서 사용자 정보 추출
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) {
      throw new BadRequestException('Authorization token required');
    }

    const payload = await TokenUtils.extractAndValidatePayload(
      token,
      TOKEN_TYPES.LOGIN,
      this.jwtService,
    );
    if (!payload) {
      throw new BadRequestException('Invalid token');
    }

    // 사용자 정보 조회
    const user = await this.oauth2Service.getUserInfo(payload.sub);
    if (!user) {
      throw new BadRequestException('User not found');
    }

    await this.scopeService.refreshCache();
    const cacheInfo = this.scopeService.getCacheInfo();

    return {
      message: 'Scopes cache refreshed successfully',
      cacheInfo,
    };
  }

  @Get('scopes/cache-info')
  @UseGuards(JwtAuthGuard, PermissionsGuard)
  @RequirePermissions(PERMISSIONS.MANAGE_SYSTEM)
  async getScopesCacheInfo(@Request() req: ExpressRequest) {
    // JWT 토큰에서 사용자 정보 추출
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) {
      throw new BadRequestException('Authorization token required');
    }

    const payload = await TokenUtils.extractAndValidatePayload(
      token,
      TOKEN_TYPES.LOGIN,
      this.jwtService,
    );
    if (!payload) {
      throw new BadRequestException('Invalid token');
    }

    // 사용자 정보 조회
    const user = await this.oauth2Service.getUserInfo(payload.sub);
    if (!user) {
      throw new BadRequestException('User not found');
    }

    // 시스템 관리자 권한 확인
    if (!PermissionUtils.isAdmin(user.permissions)) {
      throw new BadRequestException('System administrator privileges required');
    }

    return this.scopeService.getCacheInfo();
  }
}
