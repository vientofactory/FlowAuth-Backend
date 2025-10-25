import { CryptoUtils } from '../utils/crypto.util';
import { CRYPTO_VALIDATION } from '../constants/validation.constants';

describe('CryptoUtils', () => {
  describe('generateRandomString', () => {
    it('should generate a string of the specified length', () => {
      const length = 10;
      const result = CryptoUtils.generateRandomString(length);

      expect(result).toHaveLength(length);
    });

    it('should generate strings with characters from the specified charset', () => {
      const charset = 'ABC';
      const result = CryptoUtils.generateRandomString(10, charset);

      for (const char of result) {
        expect(charset).toContain(char);
      }
    });

    it('should throw error for invalid length', () => {
      expect(() => CryptoUtils.generateRandomString(0)).toThrow(
        'Length must be greater than 0',
      );
      expect(() => CryptoUtils.generateRandomString(-1)).toThrow(
        'Length must be greater than 0',
      );
    });

    it('should throw error for empty charset', () => {
      expect(() => CryptoUtils.generateRandomString(10, '')).toThrow(
        'Charset cannot be empty',
      );
    });

    it('should generate different strings on multiple calls', () => {
      const result1 = CryptoUtils.generateRandomString(32);
      const result2 = CryptoUtils.generateRandomString(32);

      expect(result1).not.toBe(result2);
    });
  });

  describe('generateState', () => {
    it('should generate a state string with default length', () => {
      const result = CryptoUtils.generateState();

      expect(result).toHaveLength(32);
    });

    it('should generate a state string with specified length', () => {
      const length = 16;
      const result = CryptoUtils.generateState(length);

      expect(result).toHaveLength(length);
    });
  });

  describe('generateCodeVerifier', () => {
    it('should generate a valid PKCE code verifier', () => {
      const result = CryptoUtils.generateCodeVerifier();

      // PKCE code_verifier should be 43-128 characters
      expect(result.length).toBeGreaterThanOrEqual(43);
      expect(result.length).toBeLessThanOrEqual(128);

      // Should only contain valid characters for base64url
      const base64urlRegex = CRYPTO_VALIDATION.BASE64URL_REGEX;
      expect(result).toMatch(base64urlRegex);
    });

    it('should generate different code verifiers on multiple calls', () => {
      const result1 = CryptoUtils.generateCodeVerifier();
      const result2 = CryptoUtils.generateCodeVerifier();

      expect(result1).not.toBe(result2);
    });
  });

  describe('generateCodeChallenge', () => {
    it('should generate S256 code challenge from code verifier', () => {
      const codeVerifier = 'test_code_verifier_12345';
      const result = CryptoUtils.generateCodeChallenge(codeVerifier);

      // S256 challenge should be base64url encoded SHA256 hash (43 characters)
      expect(result).toHaveLength(43);

      const base64urlRegex = CRYPTO_VALIDATION.BASE64URL_REGEX;
      expect(result).toMatch(base64urlRegex);
    });

    it('should generate different challenges for different verifiers', () => {
      const result1 = CryptoUtils.generateCodeChallenge('verifier1');
      const result2 = CryptoUtils.generateCodeChallenge('verifier2');

      expect(result1).not.toBe(result2);
    });
  });
});
