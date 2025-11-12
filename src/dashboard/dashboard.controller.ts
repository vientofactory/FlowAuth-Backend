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
import { PERMISSIONS } from '@flowauth/shared';
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
    summary: '최근 활동 목록 조회',
    description: `
사용자의 최근 활동 목록을 조회합니다.

**포함 정보:**
- 로그인, 토큰 발급/취소, 클라이언트 생성/수정/삭제 등의 활동
- 활동별 메타데이터 (클라이언트 정보, 토큰 정보 등)
- 페이징 지원 (limit, offset)
    `,
  })
  @ApiResponse({
    status: 200,
    description: '최근 활동 목록',
    schema: {
      type: 'object',
      properties: {
        activities: {
          type: 'array',
          items: { $ref: '#/components/schemas/RecentActivityDto' },
        },
        total: {
          type: 'number',
          description: '전체 활동 수',
        },
      },
    },
  })
  @ApiResponse({
    status: 401,
    description: '인증 필요',
  })
  @ApiQuery({
    name: 'limit',
    required: false,
    type: Number,
    description: '조회할 활동 수 (기본값: 10, 최대: 50)',
  })
  @ApiQuery({
    name: 'offset',
    required: false,
    type: Number,
    description: '건너뛸 활동 수 (기본값: 0)',
  })
  async getRecentActivities(
    @Request() req: AuthenticatedRequest,
    @Query('limit') limit?: string,
    @Query('offset') offset?: string,
  ): Promise<{ activities: RecentActivityDto[]; total: number }> {
    const limitNum = limit ? parseInt(limit, 10) : 10;
    const offsetNum = offset ? parseInt(offset, 10) : 0;
    return this.dashboardService.getRecentActivities(
      req.user.id,
      limitNum,
      offsetNum,
    );
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
  @RequirePermissions(PERMISSIONS.DELETE_TOKEN)
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({
    summary: '앱 연결 해제',
    description: `
특정 클라이언트와의 연결을 해제하고 관련 토큰을 취소합니다.
사용자는 자신이 연결한 앱의 연결만 해제할 수 있습니다.

**필요 권한:** delete:token
    `,
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

  @Get('analytics/token')
  @RequirePermissions(PERMISSIONS.READ_DASHBOARD)
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({
    summary: '토큰 분석 메트릭스',
    description: `
사용자의 토큰 사용 패턴과 성능 메트릭스를 조회합니다.

**포함 정보:**
- 시간별/요일별 토큰 사용 패턴
- 클라이언트별 성능 메트릭스
- 사용자 활동 메트릭스
- 시스템 건강 상태
    `,
  })
  @ApiResponse({
    status: 200,
    description: '토큰 분석 메트릭스 조회 성공',
  })
  @ApiResponse({
    status: 401,
    description: '인증 필요',
  })
  @ApiQuery({
    name: 'days',
    required: false,
    type: Number,
    description: '분석 기간 (일) - 기본값: 30',
  })
  async getTokenAnalytics(
    @Request() req: AuthenticatedRequest,
    @Query('days') days?: string,
  ) {
    const daysNum = days ? parseInt(days, 10) : 30;
    return this.dashboardService.getTokenAnalytics(req.user.id, daysNum);
  }

  @Get('analytics/security')
  @RequirePermissions(PERMISSIONS.READ_DASHBOARD)
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({
    summary: '보안 메트릭스',
    description: `
보안 관련 메트릭스와 트렌드를 조회합니다.

**포함 정보:**
- 보안 알림 통계
- 위험 사용자/클라이언트 분석
- 보안 점수 및 위협 수준
- 시간별 보안 트렌드
    `,
  })
  @ApiResponse({
    status: 200,
    description: '보안 메트릭스 조회 성공',
  })
  @ApiResponse({
    status: 401,
    description: '인증 필요',
  })
  @ApiQuery({
    name: 'days',
    required: false,
    type: Number,
    description: '분석 기간 (일) - 기본값: 30',
  })
  async getSecurityMetrics(
    @Request() req: AuthenticatedRequest,
    @Query('days') days?: string,
  ) {
    const daysNum = days ? parseInt(days, 10) : 30;
    return this.dashboardService.getSecurityMetrics(req.user.id, daysNum);
  }

  @Get('analytics/advanced')
  @RequirePermissions(PERMISSIONS.READ_DASHBOARD)
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({
    summary: '고급 통계 대시보드',
    description: `
토큰 분석과 보안 메트릭스를 통합한 고급 통계 정보를 조회합니다.

**포함 정보:**
- 토큰 사용 패턴 분석
- 클라이언트 성능 메트릭스
- 보안 알림 및 트렌드
- 시스템 건강 상태
- 위험 분석
    `,
  })
  @ApiResponse({
    status: 200,
    description: '고급 통계 대시보드 조회 성공',
  })
  @ApiResponse({
    status: 401,
    description: '인증 필요',
  })
  @ApiQuery({
    name: 'days',
    required: false,
    type: Number,
    description: '분석 기간 (일) - 기본값: 30',
  })
  async getAdvancedDashboardStats(
    @Request() req: AuthenticatedRequest,
    @Query('days') days?: string,
  ) {
    const daysNum = days ? parseInt(days, 10) : 30;
    return this.dashboardService.getAdvancedDashboardStats(
      req.user.id,
      daysNum,
    );
  }
}
