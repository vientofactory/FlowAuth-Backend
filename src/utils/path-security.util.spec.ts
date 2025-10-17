import {
  safePath,
  validateFilename,
  sanitizeFilename,
  validatePathInput,
  createSecureSubdirectory,
} from './path-security.util';

describe('Path Security Utilities', () => {
  const baseDir = '/tmp/test';

  describe('safePath', () => {
    it('should allow safe paths', () => {
      expect(() => safePath('file.txt', baseDir)).not.toThrow();
      expect(() => safePath('subdir/file.txt', baseDir)).not.toThrow();
    });

    it('should prevent directory traversal', () => {
      // These should throw because they contain traversal patterns
      expect(() => safePath('..', baseDir)).toThrow();
      expect(() => safePath('../etc/passwd', baseDir)).toThrow();
      expect(() => safePath('subdir/../../../etc/passwd', baseDir)).toThrow();
    });

    it('should prevent null bytes', () => {
      expect(() => safePath('file\0.txt', baseDir)).toThrow();
    });

    it('should prevent control characters', () => {
      expect(() => safePath('file\x01.txt', baseDir)).toThrow();
      expect(() => safePath('file\x1f.txt', baseDir)).toThrow();
    });

    it('should prevent absolute paths in user input', () => {
      expect(() => safePath('/etc/passwd', baseDir)).toThrow();
      // Note: Windows absolute paths might not be detected on Unix systems
      // but we still test the basic case
    });
  });

  describe('validateFilename', () => {
    it('should validate safe filenames', () => {
      expect(validateFilename('document.pdf')).toBe(true);
      expect(validateFilename('image_2023.jpg')).toBe(true);
      expect(validateFilename('file-name.txt')).toBe(true);
    });

    it('should reject dangerous filenames', () => {
      expect(validateFilename('file\0.txt')).toBe(false);
      expect(validateFilename('file..txt')).toBe(false);
      expect(validateFilename('con.txt')).toBe(false); // Windows reserved
      expect(validateFilename('file\x01.txt')).toBe(false);
    });
  });

  describe('sanitizeFilename', () => {
    it('should sanitize dangerous characters', () => {
      expect(sanitizeFilename('file<>:"|?*.txt')).toBe('file_______.txt');
      expect(sanitizeFilename('file..txt')).toBe('file_txt');
      expect(sanitizeFilename('file\0\x01.txt')).toBe('file_.txt');
    });

    it('should handle long filenames', () => {
      const longName = 'a'.repeat(300);
      const sanitized = sanitizeFilename(longName);
      expect(sanitized.length).toBeLessThanOrEqual(255);
    });
  });

  describe('validatePathInput', () => {
    it('should validate safe paths', () => {
      expect(validatePathInput('subdir')).toBe(true);
      expect(validatePathInput('user-uploads')).toBe(true);
    });

    it('should reject dangerous paths', () => {
      expect(validatePathInput('../')).toBe(false);
      expect(validatePathInput('./hidden')).toBe(false);
      expect(validatePathInput('path/with//')).toBe(false);
      expect(validatePathInput('path\\\\with')).toBe(false);
    });
  });

  describe('createSecureSubdirectory', () => {
    it('should create secure subdirectory paths', () => {
      expect(() => createSecureSubdirectory('user123', baseDir)).not.toThrow();
      expect(() =>
        createSecureSubdirectory('2023-uploads', baseDir),
      ).not.toThrow();
    });

    it('should prevent dangerous subdirectory names', () => {
      expect(() => createSecureSubdirectory('../escape', baseDir)).toThrow();
      expect(() => createSecureSubdirectory('./hidden', baseDir)).toThrow();
    });
  });
});
