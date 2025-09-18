import { NestExpressApplication } from '@nestjs/platform-express';
import { SwaggerModule } from '@nestjs/swagger';
import {
  createSwaggerConfig,
  SWAGGER_SETUP_OPTIONS,
  SWAGGER_DOCUMENT_OPTIONS,
} from './swagger.config';

/**
 * Swagger 문서화를 설정하고 초기화합니다.
 * main.ts에서 호출되는 중앙화된 Swagger 설정 함수입니다.
 *
 * @param app NestJS Express 애플리케이션 인스턴스
 */
export function setupSwagger(app: NestExpressApplication): void {
  const config = createSwaggerConfig();

  const document = SwaggerModule.createDocument(
    app,
    config,
    SWAGGER_DOCUMENT_OPTIONS,
  );

  SwaggerModule.setup('api', app, document, SWAGGER_SETUP_OPTIONS);
}

/**
 * 개발 환경에서만 Swagger를 설정합니다.
 * 프로덕션 환경에서는 Swagger를 비활성화할 수 있습니다.
 *
 * @param app NestJS Express 애플리케이션 인스턴스
 * @param nodeEnv 현재 Node.js 환경 (development, production 등)
 */
export function setupSwaggerConditionally(
  app: NestExpressApplication,
  nodeEnv?: string,
): void {
  const environment = nodeEnv || process.env.NODE_ENV;

  // 개발 환경 또는 스테이징 환경에서만 Swagger 활성화
  if (environment !== 'production') {
    setupSwagger(app);
  }
}
