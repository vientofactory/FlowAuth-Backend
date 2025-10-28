import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  HttpException,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import { Response } from 'express';
import { QueryFailedError } from 'typeorm';
import { LoggingService } from '../services/logging.service';

export interface ErrorResponse {
  error: string;
  error_description: string;
  timestamp?: string;
  path?: string;
}

@Catch()
export class GlobalExceptionFilter implements ExceptionFilter {
  private readonly logger = new Logger(GlobalExceptionFilter.name);

  catch(exception: unknown, host: ArgumentsHost): void {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();

    let status = HttpStatus.INTERNAL_SERVER_ERROR;
    let errorResponse: ErrorResponse;

    if (exception instanceof HttpException) {
      status = exception.getStatus();
      const exceptionResponse = exception.getResponse();

      if (typeof exceptionResponse === 'string') {
        errorResponse = {
          error: this.getErrorType(status),
          error_description: exceptionResponse,
        };
      } else if (
        typeof exceptionResponse === 'object' &&
        exceptionResponse !== null
      ) {
        const responseObj = exceptionResponse as Record<string, unknown>;
        errorResponse = {
          error: (responseObj.error as string) || this.getErrorType(status),
          error_description:
            (responseObj.message as string) ||
            (responseObj.error_description as string) ||
            'An error occurred',
        };
      } else {
        errorResponse = {
          error: this.getErrorType(status),
          error_description: 'An error occurred',
        };
      }
    } else if (exception instanceof QueryFailedError) {
      status = HttpStatus.BAD_REQUEST;
      const dbError = exception as QueryFailedError & { code?: string };
      errorResponse = {
        error: 'database_error',
        error_description:
          dbError.code === 'ER_DUP_ENTRY'
            ? 'Duplicate entry'
            : 'A database error occurred',
      };
      LoggingService.logError('Database', exception, {
        code: dbError.code,
      });
    } else {
      // Unexpected errors
      errorResponse = {
        error: 'internal_server_error',
        error_description: 'An unexpected error occurred',
      };
      LoggingService.logError('Unexpected', exception);
    }

    // Add metadata for debugging (only in development)
    if (process.env.NODE_ENV === 'development') {
      errorResponse.timestamp = new Date().toISOString();
      errorResponse.path = request.url;
    }

    // Enhanced logging for production
    if (process.env.NODE_ENV !== 'development') {
      LoggingService.logError(
        'Request',
        new Error(errorResponse.error_description),
        {
          url: request.url,
          method: request.method,
          status,
        },
      );
    }

    response.status(status).json(errorResponse);
  }

  private getErrorType(status: number): string {
    const errorTypes: Record<number, string> = {
      400: 'bad_request',
      401: 'unauthorized',
      403: 'forbidden',
      404: 'not_found',
      409: 'conflict',
      422: 'unprocessable_entity',
      429: 'too_many_requests',
      500: 'internal_server_error',
      502: 'bad_gateway',
      503: 'service_unavailable',
    };
    // eslint-disable-next-line security/detect-object-injection
    return errorTypes[status] || 'internal_server_error';
  }
}
