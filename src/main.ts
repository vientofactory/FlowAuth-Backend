import { NestFactory } from '@nestjs/core';
import {
  ClassSerializerInterceptor,
  INestApplication,
  Logger,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { AppModule } from './app.module';
import { Reflector } from '@nestjs/core';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import { SeedService } from './database/seed.service';
import { join } from 'path';
import { Request, Response, NextFunction } from 'express';
import { NestExpressApplication } from '@nestjs/platform-express';
import { setupSwagger } from './config/swagger.setup';
import { ValidationSanitizationPipe } from './common/validation-sanitization.pipe';

/**
 * FlowAuth Application Bootstrap
 * OAuth2 인증 시스템의 메인 진입점
 */
async function bootstrap(): Promise<void> {
  const app = await NestFactory.create<NestExpressApplication>(AppModule);
  const configService = app.get(ConfigService);
  const logger = new Logger('Bootstrap');

  // Configure application middleware and settings
  await configureApp(app, configService, logger);

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
async function configureApp(
  app: NestExpressApplication,
  configService: ConfigService,
  logger: Logger,
): Promise<void> {
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

  // Database seeding
  await seedDatabase(app, logger);

  // API documentation
  setupSwagger(app);
}

/**
 * Configure security middleware (Helmet)
 */
function configureSecurity(app: NestExpressApplication): void {
  app.use(
    helmet({
      crossOriginResourcePolicy: false, // Disable for static file CORS
      crossOriginEmbedderPolicy: false, // Disable for cross-origin embedding
      contentSecurityPolicy: false, // Disable for development flexibility
      hsts: false, // Disable HSTS for development
      noSniff: false, // Allow content type sniffing for images
    }),
  );
}

/**
 * Configure basic middleware
 */
function configureMiddleware(app: NestExpressApplication): void {
  app.use(cookieParser());
}

/**
 * Configure static file serving with CORS headers
 */
function configureStaticFiles(app: NestExpressApplication): void {
  // Custom CORS middleware for uploads path (both API and static files)
  app.use('/uploads', (req: Request, res: Response, next: NextFunction) => {
    const origin = req.headers.origin;

    // Set CORS headers for both API endpoints and static files
    res.header('Access-Control-Allow-Origin', origin || '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, HEAD, OPTIONS');
    res.header(
      'Access-Control-Allow-Headers',
      'Origin, X-Requested-With, Content-Type, Accept, Authorization, Cache-Control, Pragma',
    );
    res.header(
      'Access-Control-Expose-Headers',
      'Content-Length, Content-Type, ETag, Last-Modified',
    );
    res.header('Access-Control-Max-Age', '86400');
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Vary', 'Origin');
    res.header('Cross-Origin-Resource-Policy', 'cross-origin');

    // Set cache headers only for static file requests (not API endpoints)
    if (
      req.method === 'GET' &&
      !req.path.endsWith('/logo') &&
      !req.path.endsWith('/config')
    ) {
      res.header('Cache-Control', 'public, max-age=31536000, immutable');
    }

    // Handle preflight requests
    if (req.method === 'OPTIONS') {
      res.status(200).end();
      return;
    }

    next();
  });

  // Serve static files
  app.useStaticAssets(join(process.cwd(), 'uploads'), {
    prefix: '/uploads/',
  });
}

/**
 * Configure CORS for API endpoints
 */
function configureCORS(app: NestExpressApplication): void {
  app.enableCors({
    origin: function (origin, callback) {
      // Allow requests with no origin (mobile apps, postman, etc.)
      if (!origin) return callback(null, true);

      // Allow all origins in development
      return callback(null, true);
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'],
    allowedHeaders: [
      'Origin',
      'X-Requested-With',
      'Content-Type',
      'Accept',
      'Authorization',
      'Cache-Control',
      'X-CSRF-Token',
    ],
    exposedHeaders: ['Content-Length', 'ETag', 'Last-Modified'],
    credentials: true,
    maxAge: 86400,
    optionsSuccessStatus: 200,
  });
}

/**
 * Configure validation and serialization
 */
function configureValidation(app: NestExpressApplication): void {
  // Global validation and sanitization pipe
  app.useGlobalPipes(new ValidationSanitizationPipe());

  // Global serialization interceptor
  app.useGlobalInterceptors(new ClassSerializerInterceptor(app.get(Reflector)));
}

/**
 * Seed database with initial data
 */
async function seedDatabase(
  app: INestApplication,
  logger: Logger,
): Promise<void> {
  try {
    const seedService = app.get(SeedService);
    await seedService.seedDatabase();
    logger.log('Database seeding completed successfully');
  } catch (error: unknown) {
    logger.error('Database seeding failed:', error);
    logger.warn('Continuing with application startup despite seeding failure');
  }
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
