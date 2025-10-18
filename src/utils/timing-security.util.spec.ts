import {
  safeStringCompare,
  safeBufferCompare,
  generateSecureToken,
  safeTokenCompare,
  safeCredentialCompare,
} from './timing-security.util';

describe('TimingSecurityUtil', () => {
  describe('safeStringCompare', () => {
    it('should return true for identical strings', () => {
      const str1 = 'hello-world-123';
      const str2 = 'hello-world-123';
      expect(safeStringCompare(str1, str2)).toBe(true);
    });

    it('should return false for different strings', () => {
      const str1 = 'hello-world-123';
      const str2 = 'hello-world-456';
      expect(safeStringCompare(str1, str2)).toBe(false);
    });

    it('should return false for different length strings', () => {
      const str1 = 'short';
      const str2 = 'much-longer-string';
      expect(safeStringCompare(str1, str2)).toBe(false);
    });

    it('should handle empty strings', () => {
      expect(safeStringCompare('', '')).toBe(true);
      expect(safeStringCompare('', 'not-empty')).toBe(false);
      expect(safeStringCompare('not-empty', '')).toBe(false);
    });
  });

  describe('safeBufferCompare', () => {
    it('should return true for identical buffers', () => {
      const buf1 = Buffer.from('test-data', 'utf8');
      const buf2 = Buffer.from('test-data', 'utf8');
      expect(safeBufferCompare(buf1, buf2)).toBe(true);
    });

    it('should return false for different buffers', () => {
      const buf1 = Buffer.from('test-data-1', 'utf8');
      const buf2 = Buffer.from('test-data-2', 'utf8');
      expect(safeBufferCompare(buf1, buf2)).toBe(false);
    });

    it('should return false for different length buffers', () => {
      const buf1 = Buffer.from('short', 'utf8');
      const buf2 = Buffer.from('much-longer', 'utf8');
      expect(safeBufferCompare(buf1, buf2)).toBe(false);
    });
  });

  describe('generateSecureToken', () => {
    it('should generate token of default length', () => {
      const token = generateSecureToken();
      expect(token).toHaveLength(64); // 32 bytes = 64 hex chars
    });

    it('should generate token of specified length', () => {
      const token = generateSecureToken(16);
      expect(token).toHaveLength(32); // 16 bytes = 32 hex chars
    });

    it('should generate different tokens', () => {
      const token1 = generateSecureToken();
      const token2 = generateSecureToken();
      expect(token1).not.toBe(token2);
    });

    it('should generate hex characters only', () => {
      const token = generateSecureToken(8);
      expect(token).toMatch(/^[0-9a-f]+$/);
    });
  });

  describe('safeTokenCompare', () => {
    it('should return true for identical tokens', () => {
      const token1 = 'abc123def456';
      const token2 = 'abc123def456';
      expect(safeTokenCompare(token1, token2)).toBe(true);
    });

    it('should return false for different tokens', () => {
      const token1 = 'abc123def456';
      const token2 = 'abc123def789';
      expect(safeTokenCompare(token1, token2)).toBe(false);
    });

    it('should handle whitespace trimming', () => {
      const token1 = '  abc123def456  ';
      const token2 = 'abc123def456';
      expect(safeTokenCompare(token1, token2)).toBe(true);
    });

    it('should handle empty tokens', () => {
      expect(safeTokenCompare('', '')).toBe(true);
      expect(safeTokenCompare('', 'token')).toBe(false);
      expect(safeTokenCompare('token', '')).toBe(false);
    });
  });

  describe('safeCredentialCompare', () => {
    it('should return true for identical credentials', () => {
      const cred1 = 'secret-key-123';
      const cred2 = 'secret-key-123';
      expect(safeCredentialCompare(cred1, cred2)).toBe(true);
    });

    it('should return false for different credentials', () => {
      const cred1 = 'secret-key-123';
      const cred2 = 'secret-key-456';
      expect(safeCredentialCompare(cred1, cred2)).toBe(false);
    });

    it('should return true when both credentials are null', () => {
      expect(safeCredentialCompare(null, null)).toBe(true);
    });

    it('should return true when both credentials are undefined', () => {
      expect(safeCredentialCompare(undefined, undefined)).toBe(true);
    });

    it('should return false when one credential is null and other is not', () => {
      expect(safeCredentialCompare(null, 'secret')).toBe(false);
      expect(safeCredentialCompare('secret', null)).toBe(false);
    });

    it('should return false when one credential is undefined and other is not', () => {
      expect(safeCredentialCompare(undefined, 'secret')).toBe(false);
      expect(safeCredentialCompare('secret', undefined)).toBe(false);
    });

    it('should return false when comparing null with undefined', () => {
      expect(safeCredentialCompare(null, undefined)).toBe(false);
      expect(safeCredentialCompare(undefined, null)).toBe(false);
    });
  });
});
