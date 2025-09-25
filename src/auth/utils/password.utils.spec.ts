import { PasswordUtils } from '../utils/password.utils';

describe('PasswordUtils', () => {
  describe('hashPassword', () => {
    it('should hash a password', async () => {
      const password = 'testPassword123';
      const hashed = await PasswordUtils.hashPassword(password);

      expect(hashed).toBeDefined();
      expect(typeof hashed).toBe('string');
      expect(hashed.length).toBeGreaterThan(0);
      expect(hashed).not.toBe(password); // Should be different from original
    });

    it('should generate different hashes for same password', async () => {
      const password = 'testPassword123';
      const hash1 = await PasswordUtils.hashPassword(password);
      const hash2 = await PasswordUtils.hashPassword(password);

      expect(hash1).not.toBe(hash2); // bcrypt generates different hashes with salt
    });
  });

  describe('verifyPassword', () => {
    it('should verify correct password', async () => {
      const password = 'testPassword123';
      const hashed = await PasswordUtils.hashPassword(password);

      const isValid = await PasswordUtils.verifyPassword(password, hashed);
      expect(isValid).toBe(true);
    });

    it('should reject incorrect password', async () => {
      const password = 'testPassword123';
      const wrongPassword = 'wrongPassword456';
      const hashed = await PasswordUtils.hashPassword(password);

      const isValid = await PasswordUtils.verifyPassword(wrongPassword, hashed);
      expect(isValid).toBe(false);
    });
  });

  describe('validatePasswordStrength', () => {
    it('should validate strong password', () => {
      const password = 'StrongPass123';
      const result = PasswordUtils.validatePasswordStrength(password);

      expect(result.isValid).toBe(true);
      expect(result.message).toBeUndefined();
    });

    it('should reject password shorter than 8 characters', () => {
      const password = 'Short1';
      const result = PasswordUtils.validatePasswordStrength(password);

      expect(result.isValid).toBe(false);
      expect(result.message).toContain('at least 8 characters');
    });

    it('should reject password without lowercase letter', () => {
      const password = 'STRONGPASS123';
      const result = PasswordUtils.validatePasswordStrength(password);

      expect(result.isValid).toBe(false);
      expect(result.message).toContain('lowercase letter');
    });

    it('should reject password without uppercase letter', () => {
      const password = 'strongpass123';
      const result = PasswordUtils.validatePasswordStrength(password);

      expect(result.isValid).toBe(false);
      expect(result.message).toContain('uppercase letter');
    });

    it('should reject password without number', () => {
      const password = 'StrongPass';
      const result = PasswordUtils.validatePasswordStrength(password);

      expect(result.isValid).toBe(false);
      expect(result.message).toContain('at least one number');
    });
  });
});
