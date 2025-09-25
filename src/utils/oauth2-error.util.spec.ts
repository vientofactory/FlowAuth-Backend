import { BadRequestException } from '@nestjs/common';
import {
  mapExceptionToOAuth2Error,
  createOAuth2Error,
  type OAuth2ErrorCode,
} from '../utils/oauth2-error.util';

describe('OAuth2 Error Utils', () => {
  describe('mapExceptionToOAuth2Error', () => {
    it('should map client-related errors to invalid_client', () => {
      const error = new BadRequestException('Invalid client_id provided');

      const result = mapExceptionToOAuth2Error(error);

      expect(result.error).toBe('invalid_client');
      expect(result.error_description).toBe('Invalid client_id provided');
    });

    it('should map authorization code errors to invalid_grant', () => {
      const error = new BadRequestException('Invalid authorization code');

      const result = mapExceptionToOAuth2Error(error);

      expect(result.error).toBe('invalid_grant');
      expect(result.error_description).toBe('Invalid authorization code');
    });

    it('should map scope errors to invalid_scope', () => {
      const error = new BadRequestException('Invalid scope requested');

      const result = mapExceptionToOAuth2Error(error);

      expect(result.error).toBe('invalid_scope');
      expect(result.error_description).toBe('Invalid scope requested');
    });

    it('should map rate limit errors to temporarily_unavailable', () => {
      const error = new BadRequestException('rate limit exceeded');

      const result = mapExceptionToOAuth2Error(error);

      expect(result.error).toBe('temporarily_unavailable');
      expect(result.error_description).toBe('rate limit exceeded');
    });

    it('should default to invalid_request for unknown errors', () => {
      const error = new BadRequestException('Some unknown error');

      const result = mapExceptionToOAuth2Error(error);

      expect(result.error).toBe('invalid_request');
      expect(result.error_description).toBe('Some unknown error');
    });
  });

  describe('createOAuth2Error', () => {
    it('should create OAuth2 error response with description', () => {
      const result = createOAuth2Error(
        'invalid_request',
        'Bad request parameters',
      );

      expect(result).toEqual({
        error: 'invalid_request',
        error_description: 'Bad request parameters',
      });
    });

    it('should create OAuth2 error response without description', () => {
      const result = createOAuth2Error(
        'server_error',
        'An unexpected error occurred',
      );

      expect(result).toEqual({
        error: 'server_error',
        error_description: 'An unexpected error occurred',
      });
    });

    it('should handle all OAuth2 error codes', () => {
      const errorCodes: OAuth2ErrorCode[] = [
        'invalid_request',
        'invalid_client',
        'unauthorized_client',
        'access_denied',
        'unsupported_response_type',
        'invalid_scope',
        'invalid_grant',
        'unsupported_grant_type',
        'server_error',
        'temporarily_unavailable',
      ];

      errorCodes.forEach((code) => {
        const result = createOAuth2Error(code, 'Test error');
        expect(result.error).toBe(code);
        expect(result.error_description).toBe('Test error');
      });
    });
  });
});
