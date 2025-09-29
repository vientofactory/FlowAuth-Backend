import { Injectable } from '@nestjs/common';
import { TokenIssuanceDay } from './dashboard-stats.service';
import { DASHBOARD_CONFIG } from './dashboard.constants';

export interface InsightsData {
  totalClients: number;
  activeTokens: number;
  totalTokensIssued: number;
  expiredTokens: number;
  revokedTokens: number;
  tokenIssuanceByDay: TokenIssuanceDay[];
  tokenExpirationRate: number;
  averageTokenLifetime: number;
}

export interface InsightsResult {
  trends: string;
  recommendations: string;
  alerts: string;
}

@Injectable()
export class DashboardAnalyticsService {
  /**
   * 통계 데이터를 기반으로 인사이트를 생성
   */
  generateInsights(data: InsightsData): InsightsResult {
    const {
      tokenIssuanceByDay,
      tokenExpirationRate,
      averageTokenLifetime,
      totalTokensIssued,
    } = data;

    // 트렌드 분석
    const trends = this.analyzeTrends(tokenIssuanceByDay);

    // 추천사항 생성
    const recommendations = this.generateRecommendations({
      tokenExpirationRate,
      averageTokenLifetime,
      totalTokensIssued,
    });

    // 경고 생성
    const alerts = this.generateAlerts(data);

    return {
      trends,
      recommendations,
      alerts,
    };
  }

  /**
   * 토큰 발급 추이 트렌드 분석
   */
  private analyzeTrends(tokenIssuanceByDay: TokenIssuanceDay[]): string {
    const trendDays = DASHBOARD_CONFIG.ANALYTICS.THRESHOLDS.TREND_ANALYSIS_DAYS;

    if (!tokenIssuanceByDay || tokenIssuanceByDay.length < trendDays) {
      return '데이터가 충분하지 않아 트렌드를 분석할 수 없습니다.';
    }

    const recentDays = tokenIssuanceByDay.slice(-trendDays);
    const previousDays = tokenIssuanceByDay.slice(-trendDays * 2, -trendDays);

    const recentTotal = recentDays.reduce(
      (sum, day) => sum + (day?.count || 0),
      0,
    );
    const previousTotal = previousDays.reduce(
      (sum, day) => sum + (day?.count || 0),
      0,
    );

    if (previousTotal === 0) {
      return recentTotal > 0
        ? `최근 ${trendDays}일간 토큰 발급이 시작되었습니다.`
        : `최근 ${trendDays * 2}일간 토큰 발급 기록이 없습니다.`;
    }

    const changePercent = ((recentTotal - previousTotal) / previousTotal) * 100;

    if (Math.abs(changePercent) >= 10) {
      return `토큰 발급량이 최근 ${trendDays}일간 ${changePercent > 0 ? '증가' : '감소'}했습니다 (${Math.abs(changePercent).toFixed(1)}%).`;
    } else {
      return '토큰 발급량이 안정적으로 유지되고 있습니다.';
    }
  }

  /**
   * 보안 및 사용성 추천사항 생성
   */
  private generateRecommendations(data: {
    tokenExpirationRate: number;
    averageTokenLifetime: number;
    totalTokensIssued: number;
  }): string {
    const { tokenExpirationRate, averageTokenLifetime, totalTokensIssued } =
      data;

    const expirationWarningThreshold =
      DASHBOARD_CONFIG.ANALYTICS.THRESHOLDS.EXPIRATION_RATE_WARNING;

    if (tokenExpirationRate > expirationWarningThreshold) {
      return '토큰 만료율이 높습니다. 토큰 만료 시간을 조정하는 것을 고려해보세요.';
    }

    if (averageTokenLifetime > 720) {
      // 30일
      return '토큰 수명이 깁니다. 보안을 위해 토큰 만료 시간을 단축하는 것을 고려해보세요.';
    }

    if (totalTokensIssued > 1000) {
      return '많은 토큰이 발급되었습니다. 정기적인 토큰 검토를 권장합니다.';
    }

    return '현재 OAuth2 설정이 적절합니다.';
  }

  /**
   * 보안 경고 생성
   */
  private generateAlerts(data: InsightsData): string {
    const { tokenExpirationRate, revokedTokens, totalTokensIssued } = data;

    if (tokenExpirationRate > 30) {
      return '토큰 만료율이 30%를 초과했습니다. 즉시 검토가 필요합니다.';
    }

    if (revokedTokens > totalTokensIssued * 0.1) {
      return '취소된 토큰이 전체의 10%를 초과했습니다.';
    }

    return '';
  }

  /**
   * 토큰 만료율 계산 헬퍼
   */
  calculateTokenExpirationRate(
    expiredTokens: number,
    totalTokens: number,
  ): number {
    return totalTokens > 0 ? (expiredTokens / totalTokens) * 100 : 0;
  }

  /**
   * 토큰 수명 등급 분류
   */
  classifyTokenLifetime(hours: number): 'short' | 'medium' | 'long' {
    if (hours >= 168) return 'long'; // 7일 이상
    if (hours >= 24) return 'medium'; // 1일 이상
    return 'short'; // 1일 미만
  }
}
