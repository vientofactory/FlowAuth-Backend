import { Logger } from '@nestjs/common';

export interface LogMetadata {
  [key: string]: unknown;
}

export class LoggingService {
  private static readonly logger = new Logger('ExceptionHandler');

  static logError(
    context: string,
    error: unknown,
    metadata?: LogMetadata,
  ): void {
    const errorMessage =
      error instanceof Error ? error.message : 'Unknown error';
    const errorStack = error instanceof Error ? error.stack : undefined;

    this.logger.error(`${context}: ${errorMessage}`, {
      context,
      stack: errorStack,
      ...metadata,
    });
  }

  static logWarn(
    context: string,
    message: string,
    metadata?: LogMetadata,
  ): void {
    this.logger.warn(`${context}: ${message}`, {
      context,
      ...metadata,
    });
  }

  static logInfo(
    context: string,
    message: string,
    metadata?: LogMetadata,
  ): void {
    this.logger.log(`${context}: ${message}`, {
      context,
      ...metadata,
    });
  }
}
