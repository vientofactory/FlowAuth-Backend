import {
  isSafeUrl,
  validateOAuth2RedirectUri,
  validateWebUrl,
  isUrlSafe,
} from './url-security.util';

describe('URL Security Utilities', () => {
  describe('isSafeUrl', () => {
    it('should validate safe HTTPS URLs', () => {
      expect(isSafeUrl('https://example.com')).toBe(true);
      expect(isSafeUrl('https://sub.example.com/path')).toBe(true);
      expect(isSafeUrl('https://example.com:8080/path?query=value')).toBe(true);
    });

    it('should reject URLs with validator.js CVE-2025-56200 attack patterns', () => {
      // These attack patterns are valid in validator.js but interpreted differently by browsers
      expect(isSafeUrl('javascript://example.com/%0Aalert(1)')).toBe(false);
      expect(
        isSafeUrl('data://example.com/text/html,<script>alert(1)</script>'),
      ).toBe(false);
      expect(isSafeUrl('vbscript://example.com/%0Amsgbox(1)')).toBe(false);
    });

    it('should reject HTTP when not allowed', () => {
      expect(isSafeUrl('http://example.com')).toBe(false);
      expect(isSafeUrl('http://example.com', { allowHttp: true })).toBe(true);
    });

    it('should reject private networks when not allowed', () => {
      expect(isSafeUrl('https://localhost')).toBe(false);
      expect(isSafeUrl('https://127.0.0.1')).toBe(false);
      expect(isSafeUrl('https://192.168.1.1')).toBe(false);
      expect(isSafeUrl('https://10.0.0.1')).toBe(false);
      expect(isSafeUrl('https://172.16.0.1')).toBe(false);

      // Allow in development mode
      expect(
        isSafeUrl('https://localhost', { allowPrivateNetworks: true }),
      ).toBe(true);
    });

    it('should reject URLs with dangerous characters', () => {
      expect(isSafeUrl('https://example.com\x00')).toBe(false);
      expect(isSafeUrl('https://example.com\x01')).toBe(false);
      expect(isSafeUrl('https://example.com\n')).toBe(false);
      expect(isSafeUrl('https://example.com\r')).toBe(false);
      expect(isSafeUrl('https://example.com\t')).toBe(false);
    });

    it('should reject malformed URLs', () => {
      expect(isSafeUrl('')).toBe(false);
      expect(isSafeUrl('not-a-url')).toBe(false);
      expect(isSafeUrl('://invalid')).toBe(false);
      expect(isSafeUrl('https://')).toBe(false);
    });

    it('should enforce length limits', () => {
      const longUrl = 'https://example.com/' + 'a'.repeat(3000);
      expect(isSafeUrl(longUrl)).toBe(false);
      expect(isSafeUrl(longUrl, { maxLength: 5000 })).toBe(true);
    });

    it('should validate hostname format', () => {
      expect(isSafeUrl('https://ex-ample.com')).toBe(true);
      expect(isSafeUrl('https://example123.com')).toBe(true);
      expect(isSafeUrl('https://-example.com')).toBe(false); // starts with hyphen
      expect(isSafeUrl('https://example-.com')).toBe(false); // ends with hyphen
      expect(isSafeUrl('https://ex@mple.com')).toBe(false); // invalid characters
    });

    it('should handle protocol parsing edge cases', () => {
      // Test parsing differences between browsers and validator.js
      expect(isSafeUrl('https://example.com')).toBe(true);
      expect(isSafeUrl('HTTPS://example.com')).toBe(false); // Case sensitive
      expect(isSafeUrl('https:example.com')).toBe(false); // No slashes
    });
  });

  describe('validateOAuth2RedirectUri', () => {
    beforeEach(() => {
      // Test environment setup
      process.env.NODE_ENV = 'test';
    });

    it('should validate OAuth2 redirect URIs in production', () => {
      process.env.NODE_ENV = 'production';

      expect(validateOAuth2RedirectUri('https://myapp.com/callback')).toBe(
        true,
      );
      expect(validateOAuth2RedirectUri('http://myapp.com/callback')).toBe(
        false,
      );
      expect(validateOAuth2RedirectUri('https://localhost/callback')).toBe(
        false,
      );
    });

    it('should be more permissive in development', () => {
      process.env.NODE_ENV = 'development';

      expect(validateOAuth2RedirectUri('https://myapp.com/callback')).toBe(
        true,
      );
      expect(validateOAuth2RedirectUri('http://localhost:3000/callback')).toBe(
        true,
      );
      expect(validateOAuth2RedirectUri('http://127.0.0.1:8080/callback')).toBe(
        true,
      );
    });

    it('should reject dangerous URLs regardless of environment', () => {
      process.env.NODE_ENV = 'development';

      expect(validateOAuth2RedirectUri('javascript:alert(1)')).toBe(false);
      expect(
        validateOAuth2RedirectUri('data:text/html,<script>alert(1)</script>'),
      ).toBe(false);
      expect(validateOAuth2RedirectUri('ftp://example.com')).toBe(false);
    });
  });

  describe('validateWebUrl', () => {
    it('should only allow HTTPS URLs', () => {
      expect(validateWebUrl('https://example.com')).toBe(true);
      expect(validateWebUrl('http://example.com')).toBe(false);
    });

    it('should reject private networks', () => {
      expect(validateWebUrl('https://localhost')).toBe(false);
      expect(validateWebUrl('https://127.0.0.1')).toBe(false);
      expect(validateWebUrl('https://192.168.1.1')).toBe(false);
    });

    it('should be suitable for logo and policy URIs', () => {
      expect(validateWebUrl('https://company.com/logo.png')).toBe(true);
      expect(validateWebUrl('https://company.com/privacy-policy')).toBe(true);
      expect(validateWebUrl('https://company.com/terms-of-service')).toBe(true);
    });
  });

  describe('isUrlSafe (class-validator compatible)', () => {
    it('should be compatible with @IsUrl decorator', () => {
      expect(isUrlSafe('https://example.com')).toBe(true);
      expect(isUrlSafe('http://example.com')).toBe(false);
      expect(isUrlSafe('javascript:alert(1)')).toBe(false);
    });

    it('should provide secure alternative to validator.js isURL', () => {
      // Patterns that are problematic in validator.js CVE-2025-56200
      expect(isUrlSafe('javascript://example.com/%0Aalert(1)')).toBe(false);
      expect(
        isUrlSafe('data://example.com/text/html,<script>alert(1)</script>'),
      ).toBe(false);
    });
  });

  describe('Edge cases and security tests', () => {
    it('should handle IPv6 addresses', () => {
      expect(isSafeUrl('https://[::1]')).toBe(false); // localhost IPv6
      expect(isSafeUrl('https://[::1]', { allowPrivateNetworks: true })).toBe(
        true,
      );
      expect(isSafeUrl('https://[2001:db8::1]')).toBe(true); // public IPv6
    });

    it('should validate port numbers', () => {
      expect(isSafeUrl('https://example.com:443')).toBe(true);
      expect(isSafeUrl('https://example.com:8080')).toBe(true);
      expect(isSafeUrl('https://example.com:99999')).toBe(false); // invalid port
      expect(isSafeUrl('https://example.com:0')).toBe(false); // invalid port
    });

    it('should handle international domain names', () => {
      // Punycode domains are handled by URL constructor
      expect(isSafeUrl('https://xn--e1afmkfd.xn--p1ai')).toBe(true); // пример.рф
    });
  });
});
