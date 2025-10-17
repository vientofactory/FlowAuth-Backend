import { Logger } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import {
  CorsConfig,
  OAUTH_CLIENT_ORIGINS,
  PUBLIC_OAUTH_ENDPOINTS,
  DEVELOPMENT_ORIGINS,
  CORS_HEADERS,
} from './cors.config';

/**
 * CORS service for OAuth2/OpenID Connect provider
 */
export class CorsService {
  private readonly logger = new Logger(CorsService.name);

  /**
   * Get allowed origins from environment variables
   */
  static getAllowedOrigins(config: CorsConfig): string[] {
    const { frontendUrl, nodeEnv } = config;
    const isProduction = nodeEnv === 'production';

    if (isProduction) {
      if (frontendUrl) {
        // Support multiple frontend URLs
        const productionOrigins = frontendUrl
          .split(',')
          .map((url) => url.trim());
        return [...productionOrigins, ...DEVELOPMENT_ORIGINS];
      } else {
        console.warn(
          'FRONTEND_URL not set in production environment. Using development origins as fallback.',
        );
        return [...DEVELOPMENT_ORIGINS];
      }
    } else {
      const origins: string[] = [...DEVELOPMENT_ORIGINS];
      if (frontendUrl) {
        const additionalOrigins = frontendUrl
          .split(',')
          .map((url) => url.trim());
        origins.push(...additionalOrigins);
      }
      return [...new Set(origins)];
    }
  }

  /**
   * Check if origin is allowed for protected endpoints
   */
  static isOriginAllowed(
    origin: string | undefined,
    config: CorsConfig,
  ): boolean {
    if (!origin) return true; // Allow requests with no origin (mobile apps, server-to-server, etc.)

    const allowedOrigins = CorsService.getAllowedOrigins(config);
    const isDevelopment = config.nodeEnv === 'development';

    // In development, be more permissive for OAuth2 ecosystem
    if (isDevelopment) {
      return (
        allowedOrigins.includes(origin) ||
        origin.startsWith('http://localhost') ||
        origin.startsWith('http://127.0.0.1') ||
        origin.startsWith('https://localhost') ||
        origin.startsWith('https://127.0.0.1') ||
        (OAUTH_CLIENT_ORIGINS as readonly string[]).includes(origin)
      );
    }

    // In production, allow configured origins and some OAuth2 tools
    return (
      allowedOrigins.includes(origin) ||
      (OAUTH_CLIENT_ORIGINS as readonly string[]).includes(origin)
    );
  }

  /**
   * Check if the endpoint is a public OAuth2/OpenID Connect endpoint
   */
  static isPublicOAuthEndpoint(path: string): boolean {
    if (!path) return false;
    return (PUBLIC_OAUTH_ENDPOINTS as readonly string[]).includes(path);
  }

  /**
   * Create CORS middleware for OAuth2/OpenID Connect endpoints
   */
  static createCorsMiddleware(config: CorsConfig) {
    const logger = new Logger('CORS');

    return (req: Request, res: Response, next: NextFunction) => {
      const origin = req.headers.origin;
      const path = req.path;

      // OAuth2/OpenID Connect public endpoints - allow all origins
      if (CorsService.isPublicOAuthEndpoint(path)) {
        res.header('Access-Control-Allow-Origin', origin || '*');
        res.header('Access-Control-Allow-Credentials', 'true');
      } else if (CorsService.isOriginAllowed(origin, config)) {
        // Protected endpoints - check origin
        res.header('Access-Control-Allow-Origin', origin);
        res.header('Access-Control-Allow-Credentials', 'true');
      } else if (origin) {
        // Reject unauthorized origin for protected endpoints
        logger.warn(`CORS blocked: ${origin} -> ${path}`);
        res.status(403).json({
          error: 'forbidden',
          error_description: `Origin '${origin}' not allowed for this endpoint`,
        });
        return;
      }

      // Set common CORS headers
      res.header('Access-Control-Allow-Methods', CORS_HEADERS.ALLOW_METHODS);
      res.header('Access-Control-Allow-Headers', CORS_HEADERS.ALLOW_HEADERS);
      res.header('Access-Control-Expose-Headers', CORS_HEADERS.EXPOSE_HEADERS);
      res.header('Access-Control-Max-Age', CORS_HEADERS.MAX_AGE);
      res.header('Vary', 'Origin');

      // Handle preflight requests
      if (req.method === 'OPTIONS') {
        res.status(200).end();
        return;
      }

      next();
    };
  }
}
