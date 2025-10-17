/**
 * CORS Configuration for OAuth2/OpenID Connect Provider
 * Handles Cross-Origin Resource Sharing for different endpoint types
 */

export interface CorsConfig {
  allowedOrigins: readonly string[];
  publicEndpoints: readonly string[];
  headers: {
    readonly ALLOW_METHODS: string;
    readonly ALLOW_HEADERS: string;
    readonly EXPOSE_HEADERS: string;
    readonly MAX_AGE: string;
  };
  developmentOrigins: readonly string[];
  frontendUrl?: string;
  nodeEnv: string;
}

/**
 * OAuth2 client applications and debugging tools that are allowed
 */
export const OAUTH_CLIENT_ORIGINS = [
  // JWT debugging tools
  'https://www.jwt.io',
  'https://jwt.io',
  'https://debugger.jwt.io',

  // OAuth2 testing tools
  'https://oauthdebugger.com',
  'https://www.oauth.com',

  // Postman web client
  'https://web.postman.co',
] as const;

/**
 * Public OAuth2/OpenID Connect endpoints that should allow all origins
 * These endpoints are secured by OAuth2 mechanisms (client auth, tokens)
 */
export const PUBLIC_OAUTH_ENDPOINTS = [
  // OpenID Connect Discovery endpoints (RFC 8414)
  '/.well-known/openid-configuration',
  '/.well-known/oauth-authorization-server',
  '/.well-known/jwks.json',

  // OAuth2 Authorization endpoint (public for redirects)
  '/oauth2/authorize',

  // Token endpoint (public but secured by client authentication)
  '/oauth2/token',

  // UserInfo endpoint (public but secured by access token)
  '/oauth2/userinfo',

  // Token introspection (public but secured by client authentication)
  '/oauth2/introspect',

  // Token revocation (public but secured by client authentication)
  '/oauth2/revoke',

  // Root info endpoint
  '/',
] as const;

/**
 * Development origins that are always allowed in development mode
 */
export const DEVELOPMENT_ORIGINS = [
  'http://localhost:3000',
  'http://localhost:5173', // Vite dev server
  'http://localhost:4173', // Vite preview
  'http://127.0.0.1:3000',
  'http://127.0.0.1:5173',
] as const;

/**
 * CORS headers configuration
 */
export const CORS_HEADERS = {
  ALLOW_METHODS: 'GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD',
  ALLOW_HEADERS:
    'Origin, X-Requested-With, Content-Type, Accept, Authorization, Cache-Control, X-CSRF-Token, X-Client-Id, X-Client-Secret',
  EXPOSE_HEADERS:
    'Content-Length, ETag, Last-Modified, WWW-Authenticate, X-RateLimit-Limit, X-RateLimit-Remaining',
  MAX_AGE: '86400',
} as const;

/**
 * Default CORS configuration instance
 * OAuth2/OpenID Connect compliant CORS settings
 */
export const corsConfig: CorsConfig = {
  allowedOrigins: OAUTH_CLIENT_ORIGINS,
  publicEndpoints: PUBLIC_OAUTH_ENDPOINTS,
  headers: CORS_HEADERS,
  developmentOrigins: DEVELOPMENT_ORIGINS,
  nodeEnv: process.env.NODE_ENV || 'development',
  frontendUrl: process.env.FRONTEND_URL,
};
