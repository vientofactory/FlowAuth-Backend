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
import { ProblemDetailsUtil } from '../utils/problem-details.util';
import { ProblemDetailsDto } from '../dto/response.dto';

@Catch()
export class GlobalExceptionFilter implements ExceptionFilter {
  private readonly logger = new Logger(GlobalExceptionFilter.name);

  catch(exception: unknown, host: ArgumentsHost): void {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();

    let status = HttpStatus.INTERNAL_SERVER_ERROR;
    let problemDetails: ProblemDetailsDto;

    if (exception instanceof HttpException) {
      status = exception.getStatus();
      problemDetails = ProblemDetailsUtil.fromHttpException(
        exception,
        request.url,
      );
    } else if (exception instanceof QueryFailedError) {
      status = HttpStatus.BAD_REQUEST;
      const dbError = exception as QueryFailedError & { code?: string };
      const errorDescription =
        dbError.code === 'ER_DUP_ENTRY'
          ? 'Duplicate entry'
          : 'A database error occurred';

      problemDetails = ProblemDetailsUtil.fromError(
        new Error(errorDescription),
        status,
        request.url,
        { code: dbError.code },
      );

      LoggingService.logError('Database', exception, {
        code: dbError.code,
      });
    } else {
      // Unexpected errors
      const error =
        exception instanceof Error ? exception : new Error(String(exception));
      problemDetails = ProblemDetailsUtil.fromError(error, status, request.url);

      LoggingService.logError('Unexpected', exception);
    }

    // Enhanced logging for production
    if (process.env.NODE_ENV !== 'development') {
      LoggingService.logError(
        'Request',
        new Error(problemDetails.detail ?? problemDetails.title),
        {
          url: request.url,
          method: request.method,
          status,
        },
      );
    }

    response.status(status).json(problemDetails);
  }
}
