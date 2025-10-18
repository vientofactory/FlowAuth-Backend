import {
  Injectable,
  NestMiddleware,
  BadRequestException,
  PipeTransform,
  Logger,
} from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';

// 크기 제한 오류 클래스
class SizeLimitError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SizeLimitError';
  }
}

// 크기 제한 설정
export interface SizeLimitConfig {
  maxBodySize?: number; // 요청 본문 최대 크기 (bytes)
  maxUrlLength?: number; // URL 최대 길이
  maxHeaderSize?: number; // 헤더 최대 크기
  maxFieldLength?: number; // 개별 필드 최대 길이
}

// 기본 제한값 (보안 강화)
export const DEFAULT_SIZE_LIMITS: Required<SizeLimitConfig> = {
  maxBodySize: 1024 * 1024, // 1MB
  maxUrlLength: 2048, // 2KB
  maxHeaderSize: 8192, // 8KB
  maxFieldLength: 1000, // 1KB
};

@Injectable()
export class SizeLimitMiddleware implements NestMiddleware {
  private readonly logger = new Logger(SizeLimitMiddleware.name);
  constructor(private config: SizeLimitConfig = {}) {}

  use(req: Request, res: Response, next: NextFunction): void {
    const limits = { ...DEFAULT_SIZE_LIMITS, ...this.config };

    try {
      // URL 길이 검사
      if (req.url && req.url.length > limits.maxUrlLength) {
        throw new BadRequestException(
          `URL too long. Maximum length is ${limits.maxUrlLength} characters`,
        );
      }

      // 헤더 크기 검사
      const headersSize = JSON.stringify(req.headers).length;
      if (headersSize > limits.maxHeaderSize) {
        throw new BadRequestException(
          `Headers too large. Maximum size is ${limits.maxHeaderSize} bytes`,
        );
      }

      // Content-Length 검사 (요청 본문이 있는 경우)
      const contentLength = parseInt(req.headers['content-length'] || '0', 10);
      if (contentLength > limits.maxBodySize) {
        throw new BadRequestException(
          `Request body too large. Maximum size is ${limits.maxBodySize} bytes`,
        );
      }

      next();
    } catch (error) {
      // 에러 로깅
      this.logger.warn('Size limit violation:', {
        url: req.url,
        method: req.method,
        contentLength: req.headers['content-length'],
        userAgent: req.headers['user-agent'],
        ip: this.getClientIP(req),
        error: error instanceof Error ? error.message : 'Unknown error',
      });

      if (error instanceof BadRequestException) {
        throw error;
      }

      throw new BadRequestException('Request validation failed');
    }
  }

  private getClientIP(req: Request): string {
    return (
      (req.headers['cf-connecting-ip'] as string) ||
      (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ||
      (req.headers['x-real-ip'] as string) ||
      req.connection.remoteAddress ||
      req.socket.remoteAddress ||
      'unknown'
    );
  }
}

// 필드별 크기 제한 파이프 (기본값 사용)
export class FieldSizeLimitPipe implements PipeTransform {
  private readonly maxLength: number;

  constructor(maxLength?: number) {
    this.maxLength = maxLength ?? DEFAULT_SIZE_LIMITS.maxFieldLength;
  }

  transform(value: unknown): unknown {
    if (typeof value === 'string') {
      if (value.length > this.maxLength) {
        throw new BadRequestException(
          `Field too long. Maximum length is ${this.maxLength} characters`,
        );
      }
    } else if (Array.isArray(value)) {
      // 배열의 각 요소 검사
      value.forEach((item, index) => {
        if (typeof item === 'string' && item.length > this.maxLength) {
          throw new BadRequestException(
            `Array item at index ${index} too long. Maximum length is ${this.maxLength} characters`,
          );
        }
      });
    } else if (typeof value === 'object' && value !== null) {
      // 객체의 각 속성 검사
      Object.entries(value as Record<string, unknown>).forEach(([key, val]) => {
        if (typeof val === 'string' && val.length > this.maxLength) {
          throw new BadRequestException(
            `Field '${key}' too long. Maximum length is ${this.maxLength} characters`,
          );
        }
      });
    }

    return value;
  }
}

// 기본 필드 크기 제한 파이프 인스턴스
export const DefaultFieldSizeLimitPipe = new FieldSizeLimitPipe();

// reCAPTCHA 토큰을 위한 전용 파이프 (더 긴 필드 허용)
export const RecaptchaFieldSizeLimitPipe = new FieldSizeLimitPipe(3000);

// Express 미들웨어 팩토리 함수
export function createSizeLimitMiddleware(config: SizeLimitConfig = {}) {
  const limits = { ...DEFAULT_SIZE_LIMITS, ...config };
  const logger = new Logger('SizeLimitMiddleware');

  return (req: Request, res: Response, next: NextFunction): void => {
    try {
      // URL 길이 검사
      if (req.url && req.url.length > limits.maxUrlLength) {
        throw new SizeLimitError(
          `URL too long. Maximum length is ${limits.maxUrlLength} characters`,
        );
      }

      // 헤더 크기 검사
      const headersSize = JSON.stringify(req.headers).length;
      if (headersSize > limits.maxHeaderSize) {
        throw new SizeLimitError(
          `Headers too large. Maximum size is ${limits.maxHeaderSize} bytes`,
        );
      }

      // Content-Length 검사 (요청 본문이 있는 경우)
      const contentLength = parseInt(req.headers['content-length'] || '0', 10);
      if (contentLength > limits.maxBodySize) {
        throw new SizeLimitError(
          `Request body too large. Maximum size is ${limits.maxBodySize} bytes`,
        );
      }

      next();
    } catch (error) {
      // 에러 로깅
      logger.warn('Size limit violation:', {
        url: req.url,
        method: req.method,
        contentLength: req.headers['content-length'],
        userAgent: req.headers['user-agent'],
        ip: getClientIP(req),
        error: error instanceof Error ? error.message : 'Unknown error',
      });

      const message =
        error instanceof SizeLimitError
          ? error.message
          : 'Request validation failed';
      res.status(400).json({
        statusCode: 400,
        message,
        error: 'Bad Request',
      });
    }
  };
}

function getClientIP(req: Request): string {
  return (
    (req.headers['cf-connecting-ip'] as string) ||
    (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ||
    (req.headers['x-real-ip'] as string) ||
    req.connection.remoteAddress ||
    req.socket.remoteAddress ||
    'unknown'
  );
}

// 특정 엔드포인트용 크기 제한 데코레이터
export const FIELD_SIZE_LIMIT_KEY = 'field_size_limit';

export const FieldSizeLimit = (maxLength: number): ParameterDecorator => {
  return (
    target: object,
    propertyKey: string | symbol | undefined,
    parameterIndex: number,
  ) => {
    const existingLimits =
      (Reflect.getMetadata(
        FIELD_SIZE_LIMIT_KEY,
        target,
        propertyKey!,
      ) as Record<number, number>) || {};
    // Safe object assignment to prevent injection
    if (typeof parameterIndex === 'number' && parameterIndex >= 0) {
      Object.defineProperty(existingLimits, parameterIndex, {
        value: maxLength,
        writable: true,
        enumerable: true,
        configurable: true,
      });
    }
    Reflect.defineMetadata(
      FIELD_SIZE_LIMIT_KEY,
      existingLimits,
      target,
      propertyKey!,
    );
  };
};
