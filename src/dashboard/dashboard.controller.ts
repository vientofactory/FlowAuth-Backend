import {
  Controller,
  Get,
  UseGuards,
  Request,
  Query,
  Delete,
  Param,
  Body,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
  ApiQuery,
} from '@nestjs/swagger';
import { DashboardService } from './dashboard.service';
import { DashboardStatsResponseDto } from './dto/dashboard-stats.dto';
import { RecentActivityDto } from './dto/recent-activity.dto';
import {
  ConnectedAppsResponseDto,
  RevokeConnectionResponseDto,
} from './dto/connected-apps.dto';
import { LoginTokenGuard } from '../auth/guards/login-token.guard';
import {
  PermissionsGuard,
  RequirePermissions,
} from '../auth/permissions.guard';
import { PERMISSIONS } from '../constants/auth.constants';
import type { AuthenticatedRequest } from '../types/auth.types';

@Controller('dashboard')
@ApiTags('Dashboard')
@UseGuards(LoginTokenGuard, PermissionsGuard)
export class DashboardController {
  constructor(private readonly dashboardService: DashboardService) {}

  @Get('stats')
  @RequirePermissions(PERMISSIONS.READ_DASHBOARD)
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({
    summary: '대시보드 통계 정보',
    description: `
사용자의 OAuth2 관련 통계 정보를 조회합니다.

**포함 정보:**
- 총 클라이언트 수
- 활성 토큰 수
- 계정 생성일
    `,
  })
  @ApiResponse({
    status: 200,
    description: '대시보드 통계',
    type: DashboardStatsResponseDto,
  })
  @ApiResponse({
    status: 401,
    description: '인증 필요',
  })
  async getDashboardStats(
    @Request() req: AuthenticatedRequest,
  ): Promise<DashboardStatsResponseDto> {
    return this.dashboardService.getDashboardStats(req.user.id);
  }

  @Get('activities')
  @RequirePermissions(PERMISSIONS.READ_DASHBOARD)
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({
    summary: '최근 활동 조회',
    description: '사용자의 최근 활동 내역을 조회합니다.',
  })
  @ApiQuery({
    name: 'limit',
    description: '조회할 활동 수',
    example: 10,
    required: false,
  })
  @ApiResponse({
    status: 200,
    description: '최근 활동 목록',
    type: [RecentActivityDto],
  })
  async getRecentActivities(
    @Request() req: AuthenticatedRequest,
    @Query('limit') limit?: string,
  ): Promise<RecentActivityDto[]> {
    const limitNum = limit ? parseInt(limit, 10) : 10;
    return this.dashboardService.getRecentActivities(req.user.id, limitNum);
  }

  @Get('connected-apps')
  @RequirePermissions(PERMISSIONS.READ_DASHBOARD)
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({
    summary: '연결된 앱 목록 조회',
    description: `
사용자가 연결한 OAuth2 애플리케이션 목록을 조회합니다.

**포함 정보:**
- 앱 이름 및 설명
- 연결된 권한 범위
- 연결 일시 및 만료 일시
- 토큰 상태 (활성/만료/취소)
    `,
  })
  @ApiResponse({
    status: 200,
    description: '연결된 앱 목록',
    type: ConnectedAppsResponseDto,
  })
  @ApiResponse({
    status: 401,
    description: '인증 필요',
  })
  async getConnectedApps(
    @Request() req: AuthenticatedRequest,
  ): Promise<ConnectedAppsResponseDto> {
    return this.dashboardService.getConnectedApps(req.user.id);
  }

  @Delete('connected-apps/:clientId')
  @RequirePermissions(PERMISSIONS.WRITE_DASHBOARD)
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({
    summary: '앱 연결 해제',
    description: '특정 클라이언트와의 연결을 해제하고 관련 토큰을 취소합니다.',
  })
  @ApiResponse({
    status: 200,
    description: '연결 해제 성공',
    type: RevokeConnectionResponseDto,
  })
  @ApiResponse({
    status: 401,
    description: '인증 필요',
  })
  @ApiResponse({
    status: 404,
    description: '클라이언트를 찾을 수 없음',
  })
  async revokeConnection(
    @Request() req: AuthenticatedRequest,
    @Param('clientId') clientId: string,
  ): Promise<RevokeConnectionResponseDto> {
    return this.dashboardService.revokeConnection(
      req.user.id,
      parseInt(clientId, 10),
    );
  }
}
