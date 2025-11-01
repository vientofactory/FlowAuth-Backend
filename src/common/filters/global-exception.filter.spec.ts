import { Test, TestingModule } from '@nestjs/testing';
import { HttpException, HttpStatus } from '@nestjs/common';
import { GlobalExceptionFilter } from './global-exception.filter';
import { LoggingService } from '../services/logging.service';
import { QueryFailedError } from 'typeorm';

describe('GlobalExceptionFilter', () => {
  let filter: GlobalExceptionFilter;
  let logErrorSpy: jest.SpyInstance;

  beforeEach(async () => {
    logErrorSpy = jest.spyOn(LoggingService, 'logError').mockImplementation();

    // Set environment to development to avoid production logging
    process.env.NODE_ENV = 'development';

    const module: TestingModule = await Test.createTestingModule({
      providers: [GlobalExceptionFilter],
    }).compile();

    filter = module.get<GlobalExceptionFilter>(GlobalExceptionFilter);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  it('should be defined', () => {
    expect(filter).toBeDefined();
  });

  describe('HttpException handling', () => {
    it('should handle HttpException with string response', () => {
      const mockResponse = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn(),
      };
      const mockRequest = { url: '/test', method: 'GET' };
      const mockHost = {
        switchToHttp: jest.fn().mockReturnValue({
          getResponse: jest.fn().mockReturnValue(mockResponse),
          getRequest: jest.fn().mockReturnValue(mockRequest),
        }),
      };

      const exception = new HttpException('Test error', HttpStatus.BAD_REQUEST);

      filter.catch(exception, mockHost as any);

      expect(mockResponse.status).toHaveBeenCalledWith(HttpStatus.BAD_REQUEST);
      expect(mockResponse.json).toHaveBeenCalledWith(
        expect.objectContaining({
          type: 'https://tools.ietf.org/html/rfc7807#section-6.5.1',
          title: 'Bad Request',
          detail: 'Test error',
          status: 400,
          instance: '/test',
          extensions: {
            error: 'bad_request',
            error_description: 'Test error',
          },
        }),
      );
    });

    it('should handle HttpException with object response', () => {
      const mockResponse = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn(),
      };
      const mockRequest = { url: '/test', method: 'GET' };
      const mockHost = {
        switchToHttp: jest.fn().mockReturnValue({
          getResponse: jest.fn().mockReturnValue(mockResponse),
          getRequest: jest.fn().mockReturnValue(mockRequest),
        }),
      };

      const exception = new HttpException(
        { message: 'Custom message', error: 'custom_error' },
        HttpStatus.UNAUTHORIZED,
      );

      filter.catch(exception, mockHost as any);

      expect(mockResponse.status).toHaveBeenCalledWith(HttpStatus.UNAUTHORIZED);
      expect(mockResponse.json).toHaveBeenCalledWith(
        expect.objectContaining({
          type: 'https://tools.ietf.org/html/rfc7807#section-3.1',
          title: 'Unauthorized',
          detail: 'Custom message',
          status: 401,
          instance: '/test',
          extensions: {
            error: 'custom_error',
            error_description: 'Custom message',
          },
        }),
      );
    });

    it('should add timestamp and path in development', () => {
      process.env.NODE_ENV = 'development';

      const mockResponse = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn(),
      };
      const mockRequest = { url: '/test', method: 'GET' };
      const mockHost = {
        switchToHttp: jest.fn().mockReturnValue({
          getResponse: jest.fn().mockReturnValue(mockResponse),
          getRequest: jest.fn().mockReturnValue(mockRequest),
        }),
      };

      const exception = new HttpException('Test error', HttpStatus.BAD_REQUEST);

      filter.catch(exception, mockHost as any);

      const jsonCall = mockResponse.json.mock.calls[0][0];
      expect(jsonCall).toHaveProperty('instance', '/test');
      expect(jsonCall).not.toHaveProperty('timestamp');
      expect(jsonCall).not.toHaveProperty('path');

      process.env.NODE_ENV = 'test';
    });
  });

  describe('QueryFailedError handling', () => {
    it('should handle QueryFailedError with duplicate entry', () => {
      const mockResponse = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn(),
      };
      const mockRequest = { url: '/test', method: 'GET' };
      const mockHost = {
        switchToHttp: jest.fn().mockReturnValue({
          getResponse: jest.fn().mockReturnValue(mockResponse),
          getRequest: jest.fn().mockReturnValue(mockRequest),
        }),
      };

      const exception = new QueryFailedError(
        'Duplicate entry',
        [],
        new Error('Duplicate entry'),
      );
      (exception as any).code = 'ER_DUP_ENTRY';

      filter.catch(exception, mockHost as any);

      expect(mockResponse.status).toHaveBeenCalledWith(HttpStatus.BAD_REQUEST);
      expect(mockResponse.json).toHaveBeenCalledWith(
        expect.objectContaining({
          type: 'https://tools.ietf.org/html/rfc7807#section-6.5.1',
          title: 'Bad Request',
          detail: 'Duplicate entry',
          status: 400,
          instance: '/test',
          extensions: {
            code: 'ER_DUP_ENTRY',
          },
        }),
      );
      expect(logErrorSpy).toHaveBeenCalledWith('Database', exception, {
        code: 'ER_DUP_ENTRY',
      });
    });

    it('should handle QueryFailedError with generic database error', () => {
      const mockResponse = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn(),
      };
      const mockRequest = { url: '/test', method: 'GET' };
      const mockHost = {
        switchToHttp: jest.fn().mockReturnValue({
          getResponse: jest.fn().mockReturnValue(mockResponse),
          getRequest: jest.fn().mockReturnValue(mockRequest),
        }),
      };

      const exception = new QueryFailedError(
        'Some database error',
        [],
        new Error('Some database error'),
      );
      (exception as any).code = 'ER_UNKNOWN';

      filter.catch(exception, mockHost as any);

      expect(mockResponse.status).toHaveBeenCalledWith(HttpStatus.BAD_REQUEST);
      expect(mockResponse.json).toHaveBeenCalledWith(
        expect.objectContaining({
          type: 'https://tools.ietf.org/html/rfc7807#section-6.5.1',
          title: 'Bad Request',
          detail: 'A database error occurred',
          status: 400,
          instance: '/test',
          extensions: {
            code: 'ER_UNKNOWN',
          },
        }),
      );
      expect(logErrorSpy).toHaveBeenCalledWith('Database', exception, {
        code: 'ER_UNKNOWN',
      });
    });
  });

  describe('Unexpected error handling', () => {
    it('should handle unexpected errors', () => {
      const mockResponse = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn(),
      };
      const mockRequest = { url: '/test', method: 'GET' };
      const mockHost = {
        switchToHttp: jest.fn().mockReturnValue({
          getResponse: jest.fn().mockReturnValue(mockResponse),
          getRequest: jest.fn().mockReturnValue(mockRequest),
        }),
      };

      const exception = new Error('Unexpected error');

      filter.catch(exception, mockHost as any);

      expect(mockResponse.status).toHaveBeenCalledWith(
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
      expect(mockResponse.json).toHaveBeenCalledWith(
        expect.objectContaining({
          type: 'https://tools.ietf.org/html/rfc7807#section-6.6.1',
          title: 'Internal Server Error',
          detail: 'Unexpected error',
          status: 500,
          instance: '/test',
        }),
      );
      expect(logErrorSpy).toHaveBeenCalledWith('Unexpected', exception);
    });
  });

  describe('Production logging', () => {
    it('should log errors in production environment', () => {
      process.env.NODE_ENV = 'production';

      const mockResponse = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn(),
      };
      const mockRequest = { url: '/api/test', method: 'POST' };
      const mockHost = {
        switchToHttp: jest.fn().mockReturnValue({
          getResponse: jest.fn().mockReturnValue(mockResponse),
          getRequest: jest.fn().mockReturnValue(mockRequest),
        }),
      };

      const exception = new HttpException('Test error', HttpStatus.BAD_REQUEST);

      filter.catch(exception, mockHost as any);

      expect(logErrorSpy).toHaveBeenCalledWith('Request', expect.any(Error), {
        url: '/api/test',
        method: 'POST',
        status: HttpStatus.BAD_REQUEST,
      });

      process.env.NODE_ENV = 'development';
    });
  });
});
