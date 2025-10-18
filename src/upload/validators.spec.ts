/**
 * File upload validators test suite
 * Tests for path security module integration
 */

import {
  FileUploadValidator,
  validateFilename,
  createSafeFilePath,
  sanitizeAndValidateFilename,
} from './validators';
import type { MulterFile } from './types';

describe('FileUploadValidator with Path Security', () => {
  let validator: FileUploadValidator;

  beforeEach(() => {
    validator = new FileUploadValidator();
  });

  describe('validateFilename with path security', () => {
    it('should reject filenames with path traversal patterns', () => {
      const result = validator.validateFilename('../../../etc/passwd');
      expect(result.isValid).toBe(false);
      expect(result.error).toContain('security-forbidden');
    });

    it('should reject filenames with null bytes', () => {
      const result = validator.validateFilename('file\0name.txt');
      expect(result.isValid).toBe(false);
      expect(result.error).toContain('security-forbidden');
    });

    it('should reject hidden files', () => {
      const result = validator.validateFilename('.htaccess');
      expect(result.isValid).toBe(false);
      expect(result.error).toContain('Hidden files');
    });

    it('should accept valid filenames', () => {
      const result = validator.validateFilename('valid-file_name.jpg');
      expect(result.isValid).toBe(true);
      expect(result.sanitizedFilename).toBe('valid-file_name.jpg');
    });

    it('should reject Windows reserved names', () => {
      const result = validator.validateFilename('con.txt');
      expect(result.isValid).toBe(false);
    });
  });

  describe('createSafePath', () => {
    it('should create safe paths within base directory', () => {
      const result = validator.createSafePath('test.jpg', '/uploads');
      expect(result.success).toBe(true);
      expect(result.path).toContain('test.jpg');
    });

    it('should handle subdirectories safely', () => {
      const result = validator.createSafePath(
        'test.jpg',
        '/uploads',
        'avatars',
      );
      expect(result.success).toBe(true);
      expect(result.path).toContain('avatars');
      expect(result.path).toContain('test.jpg');
    });

    it('should reject dangerous subdirectory names', () => {
      const result = validator.createSafePath(
        'test.jpg',
        '/uploads',
        '../../../',
      );
      expect(result.success).toBe(false);
      expect(result.error).toContain('security policy');
    });
  });

  describe('validateFile with enhanced security', () => {
    const createMockFile = (
      originalname: string,
      mimetype: string = 'image/jpeg',
      size: number = 1000,
    ): MulterFile => ({
      fieldname: 'file',
      originalname,
      encoding: '7bit',
      mimetype,
      buffer: Buffer.alloc(size),
      size,
      destination: '',
      filename: '',
      path: '',
    });

    it('should validate files with security checks', () => {
      const file = createMockFile('valid-image.jpg');
      const result = validator.validateFile(file, 'avatar');

      expect(result.isValid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('should reject files with dangerous names', () => {
      const file = createMockFile('../../../dangerous.jpg');
      const result = validator.validateFile(file, 'avatar');

      expect(result.isValid).toBe(false);
      expect(
        result.errors.some((error) => error.includes('security-forbidden')),
      ).toBe(true);
    });

    it('should validate file with base directory option', () => {
      const file = createMockFile('test.jpg');
      const result = validator.validateFile(file, 'avatar', {
        baseDirectory: '/uploads',
      });

      expect(result.isValid).toBe(true);
    });
  });

  describe('convenience functions', () => {
    it('should work with standalone validateFilename function', () => {
      const result = validateFilename('test.jpg');
      expect(result.isValid).toBe(true);
    });

    it('should work with createSafeFilePath function', () => {
      const result = createSafeFilePath('test.jpg', '/uploads');
      expect(result.success).toBe(true);
    });

    it('should work with sanitizeAndValidateFilename function', () => {
      const result = sanitizeAndValidateFilename('test<file>.jpg');
      expect(result.sanitized).toBe('test_file_.jpg');
      expect(result.isValid).toBe(false); // Original filename does not comply with policy
    });
  });
});
