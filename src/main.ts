import { NestFactory } from '@nestjs/core';
import {
  ValidationPipe,
  ClassSerializerInterceptor,
  INestApplication,
  Logger,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { AppModule } from './app.module';
import { Reflector } from '@nestjs/core';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import { SeedService } from './database/seed.service';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  const configService = app.get(ConfigService);
  const logger = new Logger('Bootstrap');

  // Security
  app.use(helmet());

  // Cookie parser middleware
  app.use(cookieParser());

  // CORS
  app.enableCors({
    origin: [
      'http://localhost:5173',
      'http://localhost:5174',
      configService.get<string>('FRONTEND_URL') || 'http://localhost:5173',
    ],
    credentials: true,
  });

  // Validation
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    }),
  );

  // Serialization
  app.useGlobalInterceptors(new ClassSerializerInterceptor(app.get(Reflector)));

  // Auto-seed database on startup
  await autoSeedDatabase(app, logger);

  // Swagger API Documentation
  const config = new DocumentBuilder()
    .setTitle('FlowAuth API')
    .setDescription('FlowAuth OAuth2 시스템 API 문서')
    .addTag('auth', '인증 관련 API')
    .addTag('users', '사용자 관리 API')
    .addTag('clients', 'OAuth2 클라이언트 관리 API')
    .build();

  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api', app, document);

  const port = configService.get<number>('PORT') ?? 3000;
  await app.listen(port);
  logger.log(`Application is listening on port ${port}`);
}

async function autoSeedDatabase(
  app: INestApplication,
  logger: Logger,
): Promise<void> {
  try {
    const seedService = app.get(SeedService);
    await seedService.seedDatabase();
    logger.log('Database seeding completed successfully!');
  } catch (error: unknown) {
    logger.error('Database seeding failed:', error);
    logger.warn(
      'Continuing with application startup despite seeding failure...',
    );
  }
}

void bootstrap();
