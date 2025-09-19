import { Controller, Get, UseGuards, Request, Query } from '@nestjs/common';
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
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import type { AuthenticatedRequest } from '../types/auth.types';

@Controller('dashboard')
@ApiTags('Dashboard')
export class DashboardController {
  constructor(private readonly dashboardService: DashboardService) {}

  @Get('stats')
  @UseGuards(JwtAuthGuard)
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
  @UseGuards(JwtAuthGuard)
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
}
