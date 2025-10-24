import { NestFactory } from '@nestjs/core';
import {
  ClassSerializerInterceptor,
  INestApplication,
  Logger,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { AppModule } from './app.module';
import { Reflector } from '@nestjs/core';
import fastifyHelmet from '@fastify/helmet';
import { HelmetOptions } from 'helmet';
import fastifyCookie from '@fastify/cookie';
import { join } from 'path';
import fastifyStatic, { FastifyStaticOptions } from '@fastify/static';
import { setupSwagger } from './config/swagger.setup';
import { ValidationSanitizationPipe } from './common/validation-sanitization.pipe';
import { GlobalExceptionFilter } from './common/filters/global-exception.filter';
import { createSizeLimitMiddleware } from './common/middleware/size-limit.middleware';
import { SIZE_LIMIT_CONFIGS } from './constants/security.constants';
import { CorsService, corsConfig, CorsConfig } from './config/cors';
import {
  FastifyAdapter,
  NestFastifyApplication,
} from '@nestjs/platform-fastify';
import { FastifyPluginCallback } from 'fastify';

/**
 * FlowAuth Application Bootstrap
 * OAuth2 인증 시스템의 메인 진입점
 */
async function bootstrap(): Promise<void> {
  // Create NestJS Fastify application instance
  const app = await NestFactory.create<NestFastifyApplication>(
    AppModule,
    new FastifyAdapter(),
  );
  const configService = app.get(ConfigService);
  const logger = new Logger('Bootstrap');

  // Configure application middleware and settings
  configureApp(app);

  // Start the server
  const port = configService.get<number>('PORT') ?? 3000;
  await app.listen(port);
  logger.log(`FlowAuth server running on port ${port}`);

  // Enable graceful shutdown hooks
  app.enableShutdownHooks();

  // Handle termination signals for graceful shutdown
  process.on('SIGTERM', () => {
    logger.log('Received SIGTERM signal, starting graceful shutdown...');
    void gracefulShutdown(app, logger);
  });

  process.on('SIGINT', () => {
    logger.log('Received SIGINT signal, starting graceful shutdown...');
    void gracefulShutdown(app, logger);
  });
}

/**
 * Configure application middleware, security, and features
 */
function configureApp(app: NestFastifyApplication): void {
  // Security configuration
  configureSecurity(app);

  // Middleware configuration
  configureMiddleware(app);

  // Static file serving
  configureStaticFiles(app);

  // CORS configuration
  configureCORS(app);

  // Validation and serialization
  configureValidation(app);

  // API documentation
  setupSwagger(app);
}

/**
 * Configure security middleware (Helmet)
 */
function configureSecurity(app: NestFastifyApplication): void {
  const instance = app.getHttpAdapter().getInstance();
  const isProduction = process.env.NODE_ENV === 'production';

  const helmetOptions: HelmetOptions = {
    // Content Security Policy
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: [
          "'self'",
          "'unsafe-inline'", // For development - should be removed in production
          'https://cdnjs.cloudflare.com',
        ],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", 'data:', 'https:'],
        fontSrc: ["'self'", 'https:', 'data:'],
        connectSrc: ["'self'"],
        mediaSrc: ["'self'"],
        objectSrc: ["'none'"],
        childSrc: ["'none'"],
        frameAncestors: ["'none'"],
        baseUri: ["'self'"],
        formAction: ["'self'"],
      },
    },

    // HTTP Strict Transport Security (only in production)
    hsts: isProduction
      ? {
          maxAge: 31536000, // 1 year
          includeSubDomains: true,
          preload: true,
        }
      : false,

    // Cross-Origin policies
    crossOriginResourcePolicy: { policy: 'cross-origin' },
    crossOriginEmbedderPolicy: false, // Allow cross-origin embedding for uploads

    // Prevent MIME type sniffing
    noSniff: true,

    // Prevent clickjacking
    frameguard: { action: 'deny' },

    // Remove X-Powered-By header
    hidePoweredBy: true,

    // Referrer Policy
    referrerPolicy: { policy: ['no-referrer', 'same-origin'] },
  };

  // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-argument
  void instance.register(fastifyHelmet as any, helmetOptions as any);
}

/**
 * Configure basic middleware
 */
function configureMiddleware(app: NestFastifyApplication): void {
  const instance = app.getHttpAdapter().getInstance();

  // Register cookie plugin
  // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
  void instance.register(fastifyCookie);

  // Size limit hooks
  instance.addHook('preHandler', (request, reply, done) => {
    if (request.url.startsWith('/auth')) {
      createSizeLimitMiddleware(SIZE_LIMIT_CONFIGS.AUTH)(request, reply, done);
    } else if (request.url.startsWith('/oauth2')) {
      createSizeLimitMiddleware(SIZE_LIMIT_CONFIGS.OAUTH2)(
        request,
        reply,
        done,
      );
    } else if (request.url.startsWith('/api')) {
      createSizeLimitMiddleware(SIZE_LIMIT_CONFIGS.DEFAULT)(
        request,
        reply,
        done,
      );
    } else {
      done();
    }
  });
}

/**
 * Configure static file serving with CORS headers
 */
function configureStaticFiles(app: NestFastifyApplication): void {
  const configService = app.get(ConfigService);
  const instance = app.getHttpAdapter().getInstance();

  // Update corsConfig with current environment values
  const currentCorsConfig: CorsConfig = {
    ...corsConfig,
    frontendUrl: configService.get<string>('FRONTEND_URL'),
    nodeEnv: configService.get<string>('NODE_ENV') ?? 'development',
  };

  // Register fastify-static plugin for serving static files
  const staticOptions: FastifyStaticOptions = {
    root: join(process.cwd(), 'uploads'),
    prefix: '/uploads/',
    // do not allow directory listing
    wildcard: false,
    // let our CORS/cache middleware set headers (don't override)
    decorateReply: false,
  };
  void instance.register(
    fastifyStatic as FastifyPluginCallback<FastifyStaticOptions>,
    staticOptions,
  );

  // Custom CORS middleware for uploads path (both API and static files)
  instance.addHook('preHandler', (request, reply, done) => {
    if (!request.url.startsWith('/uploads')) {
      done();
      return;
    }

    const origin = request.headers.origin;

    // Set CORS headers with origin validation using CORS service
    if (CorsService.isOriginAllowed(origin, currentCorsConfig)) {
      reply.header('Access-Control-Allow-Origin', origin!);
    }
    reply.header('Access-Control-Allow-Methods', 'GET, POST, HEAD, OPTIONS');
    reply.header(
      'Access-Control-Allow-Headers',
      'Origin, X-Requested-With, Content-Type, Accept, Authorization, Cache-Control, Pragma',
    );
    reply.header(
      'Access-Control-Expose-Headers',
      'Content-Length, Content-Type, ETag, Last-Modified',
    );
    reply.header('Access-Control-Max-Age', '86400');
    reply.header('Access-Control-Allow-Credentials', 'true');
    reply.header('Vary', 'Origin');
    reply.header('Cross-Origin-Resource-Policy', 'cross-origin');

    // Set cache headers only for static file requests (not API endpoints)
    if (
      request.method === 'GET' &&
      !request.url.endsWith('/logo') &&
      !request.url.endsWith('/config')
    ) {
      reply.header('Cache-Control', 'public, max-age=31536000, immutable');
    }

    // Handle preflight requests
    if (request.method === 'OPTIONS') {
      reply.code(200).send();
      return;
    }

    done();
  });
}

/**
 * Configure CORS for OAuth2/OpenID Connect endpoints
 */
function configureCORS(app: NestFastifyApplication): void {
  const configService = app.get(ConfigService);
  const instance = app.getHttpAdapter().getInstance();

  // Update corsConfig with current environment values
  const currentCorsConfig: CorsConfig = {
    ...corsConfig,
    frontendUrl: configService.get<string>('FRONTEND_URL'),
    nodeEnv: configService.get<string>('NODE_ENV') ?? 'development',
  };

  // Apply CORS middleware using the new service
  instance.addHook(
    'preHandler',
    CorsService.createCorsMiddleware(currentCorsConfig),
  );
}

/**
 * Configure validation and serialization
 */
function configureValidation(app: NestFastifyApplication): void {
  // Global exception filter for consistent error handling
  app.useGlobalFilters(new GlobalExceptionFilter());

  // Global validation and sanitization pipe
  app.useGlobalPipes(new ValidationSanitizationPipe());

  // Global serialization interceptor
  app.useGlobalInterceptors(new ClassSerializerInterceptor(app.get(Reflector)));
}

// Start the application
void bootstrap().catch((error) => {
  const logger = new Logger('Bootstrap');
  logger.error('Failed to start FlowAuth server:', error);
  process.exit(1);
});

/**
 * Graceful shutdown handler
 */
async function gracefulShutdown(
  app: INestApplication,
  logger: Logger,
): Promise<void> {
  try {
    logger.log('Closing application...');
    await app.close();
    logger.log('Application closed successfully');
    process.exit(0);
  } catch (error: unknown) {
    logger.error('Error during graceful shutdown:', error);
    process.exit(1);
  }
}
