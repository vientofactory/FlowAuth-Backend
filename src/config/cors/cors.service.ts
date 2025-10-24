import { Logger } from '@nestjs/common';
import { FastifyRequest, FastifyReply } from 'fastify';
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

    return (request: FastifyRequest, reply: FastifyReply, done: () => void) => {
      const origin = request.headers.origin;
      const path = request.url;

      // OAuth2/OpenID Connect public endpoints - allow all origins
      if (CorsService.isPublicOAuthEndpoint(path)) {
        reply.header('Access-Control-Allow-Origin', origin ?? '*');
        reply.header('Access-Control-Allow-Credentials', 'true');
      } else if (CorsService.isOriginAllowed(origin, config)) {
        // Protected endpoints - check origin
        reply.header('Access-Control-Allow-Origin', origin);
        reply.header('Access-Control-Allow-Credentials', 'true');
      } else if (origin) {
        // Reject unauthorized origin for protected endpoints
        logger.warn(`CORS blocked: ${origin} -> ${path}`);
        reply.code(403).send({
          error: 'forbidden',
          error_description: `Origin '${origin}' not allowed for this endpoint`,
        });
        return;
      }

      // Set common CORS headers
      reply.header('Access-Control-Allow-Methods', CORS_HEADERS.ALLOW_METHODS);
      reply.header('Access-Control-Allow-Headers', CORS_HEADERS.ALLOW_HEADERS);
      reply.header(
        'Access-Control-Expose-Headers',
        CORS_HEADERS.EXPOSE_HEADERS,
      );
      reply.header('Access-Control-Max-Age', CORS_HEADERS.MAX_AGE);
      reply.header('Vary', 'Origin');

      // Handle preflight requests
      if (request.method === 'OPTIONS') {
        reply.code(200).send();
        return;
      }

      done();
    };
  }
}
