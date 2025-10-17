/**
 * CORS utility functions for testing and debugging
 */

import { CorsService } from './cors.service';
import { CorsConfig } from './cors.config';

export class CorsUtils {
  /**
   * Test CORS configuration for different scenarios
   */
  static testCorsConfiguration(config: CorsConfig) {
    const testOrigins = [
      'https://www.jwt.io',
      'https://localhost:3000',
      'http://localhost:5173',
      'https://oauthdebugger.com',
      'https://malicious-site.com',
      undefined, // No origin
    ];

    const testPaths = [
      '/.well-known/openid-configuration',
      '/.well-known/jwks.json',
      '/oauth2/authorize',
      '/oauth2/token',
      '/api/admin/users',
      '/uploads/avatar.jpg',
    ];

    // Only log in development environment to reduce noise
    if (process.env.NODE_ENV === 'development') {
      console.log('CORS Configuration Test Results:');
      console.log('================================');

      testOrigins.forEach((origin) => {
        console.log(`\nOrigin: ${origin || 'No Origin'}`);
        console.log('-'.repeat(40));

        testPaths.forEach((path) => {
          const isPublic = CorsService.isPublicOAuthEndpoint(path);
          const isAllowed = CorsService.isOriginAllowed(origin, config);

          let result: string;
          if (isPublic) {
            result = '✅ ALLOWED (Public OAuth endpoint)';
          } else if (isAllowed) {
            result = '✅ ALLOWED (Trusted origin)';
          } else if (!origin) {
            result = '✅ ALLOWED (No origin)';
          } else {
            result = '❌ BLOCKED (Unauthorized origin)';
          }

          console.log(`${path}: ${result}`);
        });
      });

      console.log('\n================================');
      console.log('Test completed.');
    }
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
Frontend URL: ${config.frontendUrl || 'Not configured'}
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
