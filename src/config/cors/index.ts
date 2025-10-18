/**
 * CORS Configuration Module
 *
 * This module provides OAuth2/OpenID Connect compliant CORS configuration
 * for FlowAuth backend. It separates public endpoints (OAuth2 standards)
 * from protected endpoints (application-specific APIs).
 */

export * from './cors.config';
export * from './cors.service';
export * from './cors.utils';

// Re-export commonly used types and constants
export type { CorsConfig } from './cors.config';
export {
  OAUTH_CLIENT_ORIGINS,
  PUBLIC_OAUTH_ENDPOINTS,
  DEVELOPMENT_ORIGINS,
  CORS_HEADERS,
  corsConfig,
} from './cors.config';
export { CorsService } from './cors.service';
export { CorsUtils } from './cors.utils';
