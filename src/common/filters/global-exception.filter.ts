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
      // Database errors
      status = HttpStatus.BAD_REQUEST;
      errorResponse = {
        error: 'database_error',
        error_description: 'A database error occurred',
      };
      this.logger.error('Database error:', exception);
    } else {
      // Unexpected errors
      errorResponse = {
        error: 'internal_server_error',
        error_description: 'An unexpected error occurred',
      };
      this.logger.error('Unexpected error:', exception);
    }

    // Add metadata for debugging (only in development)
    if (process.env.NODE_ENV === 'development') {
      errorResponse.timestamp = new Date().toISOString();
      errorResponse.path = request.url;
    }

    response.status(status).json(errorResponse);
  }

  private getErrorType(status: number): string {
    switch (status) {
      case 400:
        return 'bad_request';
      case 401:
        return 'unauthorized';
      case 403:
        return 'forbidden';
      case 404:
        return 'not_found';
      case 409:
        return 'conflict';
      case 429:
        return 'too_many_requests';
      default:
        return 'internal_server_error';
    }
  }
}
