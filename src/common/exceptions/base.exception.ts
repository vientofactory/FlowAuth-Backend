import { HttpException, HttpStatus } from '@nestjs/common';
import { ErrorCode } from '@flowauth/shared';

export interface ErrorDetails {
  [key: string]: unknown;
}

export abstract class BaseException extends HttpException {
  public readonly errorCode: ErrorCode;

  constructor(
    message: string,
    status: HttpStatus,
    errorCode: ErrorCode,
    details?: ErrorDetails,
  ) {
    super(
      {
        message,
        error: errorCode as string,
        timestamp: new Date().toISOString(),
        ...(details as Record<string, unknown>),
      } as Record<string, unknown>,
      status,
    );

    this.errorCode = errorCode;
  }
}
