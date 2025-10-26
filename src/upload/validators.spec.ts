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

  // Helper function for creating mock files
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

  describe('Edge Cases and Security Tests', () => {
    describe('Extreme Filename Edge Cases', () => {
      it('should handle extremely long filenames', () => {
        const longFilename = 'a'.repeat(300) + '.jpg';
        const result = validator.validateFilename(longFilename);
        expect(result.isValid).toBe(false);
        expect(result.error).toContain('too long');
      });

      it('should handle filenames with only dots', () => {
        const result1 = validator.validateFilename('.');
        const result2 = validator.validateFilename('..');
        const result3 = validator.validateFilename('...');

        expect(result1.isValid).toBe(false);
        expect(result2.isValid).toBe(false);
        expect(result3.isValid).toBe(false);
      });

      it('should handle filenames with Unicode characters', () => {
        const unicodeFilename = 'test_файл_テスト_测试.jpg';
        const result = validator.validateFilename(unicodeFilename);
        expect(result.isValid).toBe(false); // Current pattern only allows ASCII
      });

      it('should handle filenames with mixed case and numbers', () => {
        const mixedFilename = 'Test123_FILE-name.JPG';
        const result = validator.validateFilename(mixedFilename);
        expect(result.isValid).toBe(true);
      });

      it('should handle empty and whitespace-only filenames', () => {
        const emptyResult = validator.validateFilename('');
        const whitespaceResult = validator.validateFilename('   ');
        const tabResult = validator.validateFilename('\t\t');

        expect(emptyResult.isValid).toBe(false);
        expect(whitespaceResult.isValid).toBe(false);
        expect(tabResult.isValid).toBe(false);
      });
    });

    describe('Advanced Path Traversal Tests', () => {
      it('should detect various path traversal patterns', () => {
        const patterns = [
          '../../../etc/passwd',
          '..\\..\\..\\windows\\system32',
          './.././.././../etc/passwd',
          '....//....//....//etc/passwd',
        ];

        patterns.forEach((pattern) => {
          const result = validator.validateFilename(pattern);
          expect(result.isValid).toBe(false);
          expect(result.error).toContain('security-forbidden');
        });

        // Encoded patterns may trigger different validation rules
        const encodedPatterns = [
          '%2e%2e%2f%2e%2e%2f%2e%2e%2f',
          '..%252f..%252f..%252f',
          '..%c0%af..%c0%af..%c0%af',
        ];

        encodedPatterns.forEach((pattern) => {
          const result = validator.validateFilename(pattern);
          expect(result.isValid).toBe(false);
          // These may trigger the disallowed characters rule instead
          expect(result.error).toMatch(
            /security-forbidden|disallowed characters/,
          );
        });
      });

      it('should detect null byte injection', () => {
        const nullBytePatterns = [
          'test.jpg\0.exe',
          'document.pdf\0/../../../etc/passwd',
          'image\0<script>alert()</script>.png',
        ];

        nullBytePatterns.forEach((pattern) => {
          const result = validator.validateFilename(pattern);
          expect(result.isValid).toBe(false);
        });
      });

      it('should detect Windows reserved names', () => {
        const reservedNames = [
          'CON.txt',
          'PRN.jpg',
          'AUX.pdf',
          'NUL.doc',
          'COM1.exe',
          'LPT1.bat',
          'con.txt', // lowercase
          'nul.jpg', // lowercase
        ];

        reservedNames.forEach((name) => {
          const result = validator.validateFilename(name);
          expect(result.isValid).toBe(false);
        });
      });
    });

    describe('File Content Security Edge Cases', () => {
      const createAdvancedMockFile = (
        originalname: string,
        mimetype: string = 'image/jpeg',
        content: Buffer | string = Buffer.alloc(1000),
        size?: number,
      ): MulterFile => {
        const buffer = Buffer.isBuffer(content)
          ? content
          : Buffer.from(content);
        return {
          fieldname: 'file',
          originalname,
          encoding: '7bit',
          mimetype,
          buffer,
          size: size ?? buffer.length,
          destination: '',
          filename: '',
          path: '',
        };
      };

      it('should handle polyglot files (valid as multiple formats)', () => {
        const polyglotContent = Buffer.concat([
          Buffer.from([0xff, 0xd8, 0xff, 0xe0]), // JPEG magic
          Buffer.from('PADDING_DATA'),
          Buffer.from([0x50, 0x4b, 0x03, 0x04]), // ZIP magic
          Buffer.from('<script>alert("polyglot")</script>'),
        ]);

        const file = createAdvancedMockFile(
          'polyglot.jpg',
          'image/jpeg',
          polyglotContent,
        );
        const result = validator.validateFile(file, 'avatar');

        expect(result.isValid).toBe(true); // Basic validation passes, but content analysis would catch issues
      });

      it('should handle files with suspicious embedded content', () => {
        const suspiciousContent = Buffer.concat([
          Buffer.from([0xff, 0xd8, 0xff, 0xe0]),
          Buffer.from('<script>eval("malicious()")</script>'),
          Buffer.from('DROP TABLE users;'),
          Buffer.from('system("rm -rf /");'),
        ]);

        const file = createAdvancedMockFile(
          'suspicious.jpg',
          'image/jpeg',
          suspiciousContent,
        );
        const result = validator.validateFile(file, 'avatar');

        // Basic validation might pass, but enhanced validation would catch this
        expect(result.isValid).toBe(true); // Since we're using basic validateFile method
      });

      it('should handle extremely large files', () => {
        const largeSize = 100 * 1024 * 1024; // 100MB
        const file = createAdvancedMockFile(
          'huge.jpg',
          'image/jpeg',
          Buffer.alloc(1000),
          largeSize,
        );
        const result = validator.validateFile(file, 'avatar');

        expect(result.isValid).toBe(false);
        expect(result.errors.some((error) => error.includes('too large'))).toBe(
          true,
        );
      });

      it('should handle files with invalid size properties', () => {
        const file = createAdvancedMockFile('test.jpg', 'image/jpeg');

        // Test negative size
        file.size = -1;
        const negativeResult = validator.validateFile(file, 'avatar');
        expect(negativeResult.isValid).toBe(false);

        // Test NaN size
        file.size = NaN;
        const nanResult = validator.validateFile(file, 'avatar');
        expect(nanResult.isValid).toBe(false);

        // Test undefined size
        const fileWithUndefinedSize = createMockFile('test.jpg');

        delete (fileWithUndefinedSize as any).size;
        const undefinedResult = validator.validateFile(
          fileWithUndefinedSize,
          'avatar',
        );
        expect(undefinedResult.isValid).toBe(false);
      });

      it('should handle files with mismatched extensions', () => {
        const testCases = [
          { name: 'document.exe', mime: 'image/jpeg' },
          { name: 'script.js', mime: 'image/png' },
          { name: 'style.css', mime: 'application/pdf' },
          { name: 'malware.bat', mime: 'text/plain' },
        ];

        testCases.forEach(({ name, mime }) => {
          const file = createAdvancedMockFile(name, mime);
          const result = validator.validateFile(file, 'avatar');

          expect(result.isValid).toBe(false);
          expect(
            result.errors.some(
              (error) =>
                error.includes('does not match MIME type') ||
                error.includes('not allowed'),
            ),
          ).toBe(true);
        });
      });
    });

    describe('Memory and Performance Edge Cases', () => {
      it('should handle validation of many files efficiently', () => {
        const startTime = Date.now();
        const files: MulterFile[] = [];

        // Create 100 test files
        for (let i = 0; i < 100; i++) {
          const file = createMockFile(`test-${i}.jpg`);
          files.push(file);
        }

        // Validate all files
        files.forEach((file) => {
          validator.validateFile(file, 'avatar');
        });

        const endTime = Date.now();
        expect(endTime - startTime).toBeLessThan(5000); // Should complete within 5 seconds
      });

      it('should handle concurrent validations', async () => {
        const promises: Promise<any>[] = [];

        for (let i = 0; i < 50; i++) {
          const file = createMockFile(`concurrent-${i}.jpg`);
          promises.push(
            new Promise((resolve) => {
              const result = validator.validateFile(file, 'avatar');
              resolve(result);
            }),
          );
        }

        const results = await Promise.all(promises);
        expect(results.length).toBe(50);
        results.forEach((result) => {
          expect(result).toHaveProperty('isValid');
        });
      });
    });

    describe('Configuration Edge Cases', () => {
      it('should handle missing upload config gracefully', () => {
        const file = createMockFile('test.jpg');

        const result = validator.validateFile(file, 'nonexistent' as any);

        expect(result.isValid).toBe(false);
        expect(result.errors).toContain('Unsupported file type: nonexistent');
      });

      it('should handle validator with disabled buffer analysis', () => {
        const fastValidator = new FileUploadValidator({
          enableBufferAnalysis: false,
        });
        const file = createMockFile('test.jpg');
        const result = fastValidator.validateFile(file, 'avatar');

        expect(result.isValid).toBe(true);
      });
    });

    describe('Cross-Platform Compatibility', () => {
      it('should handle Windows-style paths in filenames', () => {
        const windowsPaths = [
          'C:\\Windows\\System32\\malware.exe',
          'D:\\Users\\..\\..\\sensitive.txt',
          'E:\\Temp\\test.jpg',
        ];

        windowsPaths.forEach((path) => {
          const result = validator.validateFilename(path);
          expect(result.isValid).toBe(false);
          expect(result.error).toContain('security-forbidden');
        });
      });

      it('should handle Unix-style paths in filenames', () => {
        const unixPaths = [
          '/etc/passwd',
          '/bin/bash',
          '/home/user/../../../root/.ssh/id_rsa',
        ];

        unixPaths.forEach((path) => {
          const result = validator.validateFilename(path);
          expect(result.isValid).toBe(false);
          expect(result.error).toContain('security-forbidden');
        });
      });
    });

    describe('Boundary Value Testing', () => {
      it('should handle filename exactly at length limit', () => {
        const exactLimitFilename = 'a'.repeat(251) + '.jpg'; // Exactly 255 chars
        const result = validator.validateFilename(exactLimitFilename);
        expect(result.isValid).toBe(true);
      });

      it('should handle filename one character over limit', () => {
        const overLimitFilename = 'a'.repeat(252) + '.jpg'; // 256 chars
        const result = validator.validateFilename(overLimitFilename);
        expect(result.isValid).toBe(false);
      });

      it('should handle zero-byte files', () => {
        const zeroByteFile = createMockFile('empty.jpg', 'image/jpeg', 0);
        const result = validator.validateFile(zeroByteFile, 'avatar');
        expect(result.isValid).toBe(false);
        expect(
          result.errors.some((error) => error.includes('Empty files')),
        ).toBe(true);
      });

      it('should handle files at exact size limit', () => {
        // Avatar config has 1MB limit, test just under it
        const file = createMockFile(
          'boundary.jpg',
          'image/jpeg',
          1 * 1024 * 1024 - 1,
        ); // Just under 1MB
        const result = validator.validateFile(file, 'avatar');
        expect(result.isValid).toBe(true);
      });
    });
  });
});
