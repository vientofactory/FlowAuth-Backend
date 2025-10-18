import {
  isSafeUrl,
  validateOAuth2RedirectUri,
  validateWebUrl,
} from './url-security.util';

describe('URL Security Utility - IPv6 Validation', () => {
  describe('Valid IPv6 URLs', () => {
    const validIPv6Cases = [
      'https://[2001:db8::1]/',
      'https://[2001:0db8:0000:0000:0000:ff00:0042:8329]/',
      'https://[2001:db8:0:0:1:0:0:1]/',
      'https://[::1]/',
      'https://[::ffff:192.0.2.1]/', // IPv4-mapped
      'https://[2001:db8::8a2e:370:7334]/',
    ];

    test.each(validIPv6Cases)('should accept valid IPv6 URL: %s', (url) => {
      expect(
        isSafeUrl(url, {
          allowedProtocols: ['https:'],
          allowPrivateNetworks: true,
        }),
      ).toBe(true);
    });
  });

  describe('Invalid IPv6 URLs', () => {
    const invalidIPv6Cases = [
      'https://[2001:db8::1::2]/', // Multiple compressions
      'https://[2001:db8:0:0:0:0:0:0:1]/', // Too many groups
      'https://[2001:db8::gggg]/', // Invalid hex
      'https://[2001:db8::12345]/', // Group too long
      'https://[::192.0.2.999]/', // Invalid IPv4 in mapped address
      'https://[2001:db8:]/', // Incomplete
      'https://[:]/', // Empty
    ];

    test.each(invalidIPv6Cases)('should reject invalid IPv6 URL: %s', (url) => {
      expect(
        isSafeUrl(url, {
          allowedProtocols: ['https:'],
          allowPrivateNetworks: true,
        }),
      ).toBe(false);
    });
  });

  describe('IPv6 Private Network Detection', () => {
    const privateIPv6Cases = [
      'https://[::1]/', // Loopback
      'https://[fe80::1]/', // Link-local
      'https://[fc00::1]/', // Unique local
      'https://[fd00::1]/', // Unique local
      'https://[fec0::1]/', // Site-local (deprecated)
      'https://[::ffff:192.168.1.1]/', // IPv4-mapped private
      'https://[::ffff:10.0.0.1]/', // IPv4-mapped private
    ];

    test.each(privateIPv6Cases)(
      'should detect private IPv6 network: %s',
      (url) => {
        expect(
          isSafeUrl(url, {
            allowedProtocols: ['https:'],
            allowPrivateNetworks: false,
          }),
        ).toBe(false);
      },
    );

    test.each(privateIPv6Cases)(
      'should allow private IPv6 network when permitted: %s',
      (url) => {
        expect(
          isSafeUrl(url, {
            allowedProtocols: ['https:'],
            allowPrivateNetworks: true,
          }),
        ).toBe(true);
      },
    );
  });

  describe('OAuth2 Redirect URI Validation', () => {
    test('should validate IPv6 redirect URIs in production', () => {
      process.env.NODE_ENV = 'production';

      // Should reject HTTP with IPv6
      expect(validateOAuth2RedirectUri('http://[2001:db8::1]/callback')).toBe(
        false,
      );

      // Should accept HTTPS with public IPv6
      expect(validateOAuth2RedirectUri('https://[2001:db8::1]/callback')).toBe(
        true,
      );

      // Should reject private IPv6 in production
      expect(validateOAuth2RedirectUri('https://[::1]/callback')).toBe(false);
    });

    test('should validate IPv6 redirect URIs in development', () => {
      process.env.NODE_ENV = 'development';

      // Should accept HTTP with IPv6 in development
      expect(validateOAuth2RedirectUri('http://[::1]/callback')).toBe(true);

      // Should accept private IPv6 in development
      expect(validateOAuth2RedirectUri('https://[fc00::1]/callback')).toBe(
        true,
      );
    });
  });

  describe('Web URL Validation', () => {
    test('should only accept HTTPS IPv6 URLs', () => {
      expect(validateWebUrl('https://[2001:db8::1]/')).toBe(true);
      expect(validateWebUrl('http://[2001:db8::1]/')).toBe(false);
      expect(validateWebUrl('https://[::1]/')).toBe(false); // Private
    });
  });
});
