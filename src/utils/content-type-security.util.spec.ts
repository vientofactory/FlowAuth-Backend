import {
  validateFileContent,
  isFileContentSafe,
  ContentTypeSecurityValidator,
  enableBufferAnalysisGlobally,
  disableBufferAnalysisGlobally,
  isBufferAnalysisEnabledGlobally,
  getMimeTypeFromContent,
} from './content-type-security.util';

describe('Content Type Security Utility (Refactored)', () => {
  let validator: ContentTypeSecurityValidator;

  beforeEach(() => {
    enableBufferAnalysisGlobally();
    validator = new ContentTypeSecurityValidator();
  });

  afterEach(() => {
    enableBufferAnalysisGlobally();
  });

  describe('Buffer Analysis Engine Controls', () => {
    it('should allow enabling/disabling buffer analysis globally', () => {
      enableBufferAnalysisGlobally();
      expect(isBufferAnalysisEnabledGlobally()).toBe(true);

      disableBufferAnalysisGlobally();
      expect(isBufferAnalysisEnabledGlobally()).toBe(false);

      enableBufferAnalysisGlobally();
      expect(isBufferAnalysisEnabledGlobally()).toBe(true);
    });

    it('should allow enabling/disabling buffer analysis on validator instance', () => {
      expect(validator.isBufferAnalysisEnabled()).toBe(true);

      validator.disableBufferAnalysis();
      expect(validator.isBufferAnalysisEnabled()).toBe(false);

      validator.enableBufferAnalysis();
      expect(validator.isBufferAnalysisEnabled()).toBe(true);
    });

    it('should create validator with buffer analysis disabled via config', () => {
      const validatorWithDisabledAnalysis = new ContentTypeSecurityValidator({
        enableBufferAnalysis: false,
      });

      expect(validatorWithDisabledAnalysis.isBufferAnalysisEnabled()).toBe(
        false,
      );
    });
  });

  describe('Basic Functionality', () => {
    it('should validate legitimate JPEG files', async () => {
      const jpegBuffer = Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10]);
      const result = await validateFileContent(
        jpegBuffer,
        'test.jpg',
        'image/jpeg',
      );

      expect(result.isValid).toBe(true);
      expect(result.errors).toHaveLength(0);
      expect(result.securityScore).toBeGreaterThan(70);
      expect(result.bufferAnalysisResult).toBeDefined();
      expect(result.bufferAnalysisResult?.analysisSkipped).toBe(false);
    });

    it('should return true for safe files', () => {
      const safeBuffer = Buffer.from([0xff, 0xd8, 0xff, 0xe0]);
      const result = isFileContentSafe(safeBuffer, 'test.jpg', 'image/jpeg');
      expect(result).toBe(true);
    });

    it('should work when buffer analysis is disabled', async () => {
      validator.disableBufferAnalysis();

      const jpegBuffer = Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10]);
      const result = await validator.validateFileContent(
        jpegBuffer,
        'test.jpg',
        'image/jpeg',
      );

      expect(result.isValid).toBe(true);
      expect(result.bufferAnalysisResult?.analysisSkipped).toBe(true);
      expect(result.bufferAnalysisResult?.skipReason).toBe(
        'Buffer analysis engine is disabled',
      );
      expect(result.detectedMimeType).toBeNull();
    });
  });

  describe('Advanced Security Features', () => {
    it('should detect MIME type spoofing', async () => {
      const maliciousBuffer = Buffer.from([0x4d, 0x5a, 0x90, 0x00]);
      const result = await validateFileContent(
        maliciousBuffer,
        'fake.jpg',
        'image/jpeg',
      );

      expect(result.isValid).toBe(false);
      expect(result.isSpoofed).toBe(true);
      expect(result.errors.length).toBeGreaterThan(0);
    });

    it('should detect dangerous executable files', async () => {
      const executableBuffer = Buffer.from([0x4d, 0x5a]);
      const result = await validateFileContent(
        executableBuffer,
        'malware.exe',
        'application/x-msdownload',
      );

      expect(result.isValid).toBe(false);
      expect(result.errors).toContain('Dangerous file type detected');
    });

    it('should detect embedded suspicious patterns', async () => {
      const maliciousImageBuffer = Buffer.concat([
        Buffer.from([0xff, 0xd8, 0xff, 0xe0]),
        Buffer.from('<script>alert("malicious")</script>'),
      ]);

      const result = await validateFileContent(
        maliciousImageBuffer,
        'malicious.jpg',
        'image/jpeg',
      );

      expect(result.securityScore).toBeLessThan(100);
      expect(result.bufferAnalysisResult?.hasSuspiciousPatterns).toBe(true);
      expect(result.bufferAnalysisResult?.suspiciousPatterns).toContain(
        'HTML Script Tag',
      );
    });
  });

  describe('Buffer Analysis Controls', () => {
    it('should work with buffer analysis disabled', () => {
      const suspiciousBuffer = Buffer.concat([
        Buffer.from([0xff, 0xd8, 0xff, 0xe0]),
        Buffer.from('<script>alert("test")</script>'),
      ]);

      const resultEnabled = isFileContentSafe(
        suspiciousBuffer,
        'test.jpg',
        'image/jpeg',
        true,
      );

      const resultDisabled = isFileContentSafe(
        suspiciousBuffer,
        'test.jpg',
        'image/jpeg',
        false,
      );

      expect(resultEnabled).toBe(false);
      expect(resultDisabled).toBe(true);
    });

    it('should return correct MIME types when enabled/disabled', () => {
      const jpegBuffer = Buffer.from([0xff, 0xd8, 0xff, 0xe0]);

      const mimeTypeEnabled = getMimeTypeFromContent(jpegBuffer, true);
      expect(mimeTypeEnabled).toBe('image/jpeg');

      const mimeTypeDisabled = getMimeTypeFromContent(jpegBuffer, false);
      expect(mimeTypeDisabled).toBeNull();
    });
  });

  describe('False Positive Mitigation', () => {
    it('should allow selective disabling for false positives', async () => {
      const problematicBuffer = Buffer.concat([
        Buffer.from([0xff, 0xd8, 0xff, 0xe0]),
        Buffer.from('This file contains eval() for legitimate purposes'),
      ]);

      const validatorEnabled = new ContentTypeSecurityValidator({
        enableBufferAnalysis: true,
      });
      const resultEnabled = await validatorEnabled.validateFileContent(
        problematicBuffer,
        'legitimate.jpg',
        'image/jpeg',
      );

      const validatorDisabled = new ContentTypeSecurityValidator({
        enableBufferAnalysis: false,
      });
      const resultDisabled = await validatorDisabled.validateFileContent(
        problematicBuffer,
        'legitimate.jpg',
        'image/jpeg',
      );

      expect(resultDisabled.securityScore).toBeGreaterThan(
        resultEnabled.securityScore,
      );
      expect(resultDisabled.bufferAnalysisResult?.analysisSkipped).toBe(true);
    });
  });
});
