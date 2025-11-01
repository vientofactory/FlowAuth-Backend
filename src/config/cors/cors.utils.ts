/**
 * CORS utility functions for testing and debugging
 */

import { CorsService } from './cors.service';
import { CorsConfig } from './cors.config';

export class CorsUtils {
  /**
   * Test CORS configuration for different scenarios
   */
  static testCorsConfiguration() {
    // CORS configuration testing disabled in production
  }

  /**
   * Get CORS configuration summary
   */
  static getCorsConfigSummary(config: CorsConfig): string {
    const allowedOrigins = CorsService.getAllowedOrigins(config);

    return `
CORS Configuration Summary
==========================
Environment: ${config.nodeEnv}
Frontend URL: ${config.frontendUrl ?? 'Not configured'}
Allowed Origins: ${allowedOrigins.length} total
- ${allowedOrigins.join('\n- ')}

Public OAuth Endpoints: Always allow all origins
Protected Endpoints: Only allow trusted origins
    `;
  }

  /**
   * Validate CORS configuration
   */
  static validateCorsConfig(config: CorsConfig): {
    valid: boolean;
    warnings: string[];
  } {
    const warnings: string[] = [];

    if (config.nodeEnv === 'production' && !config.frontendUrl) {
      warnings.push('FRONTEND_URL not set in production environment');
    }

    if (config.nodeEnv !== 'production' && config.nodeEnv !== 'development') {
      warnings.push(`Unknown NODE_ENV: ${config.nodeEnv}`);
    }

    const allowedOrigins = CorsService.getAllowedOrigins(config);
    if (allowedOrigins.length === 0) {
      warnings.push('No allowed origins configured');
    }

    return {
      valid: warnings.length === 0,
      warnings,
    };
  }
}
