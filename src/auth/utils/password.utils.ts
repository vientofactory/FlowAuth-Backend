import * as bcrypt from 'bcrypt';
import { AUTH_CONSTANTS } from '@flowauth/shared';
import { PASSWORD_VALIDATION } from '../../constants/validation.constants';

export class PasswordUtils {
  /**
   * 비밀번호 해싱
   */
  static async hashPassword(password: string): Promise<string> {
    return bcrypt.hash(password, AUTH_CONSTANTS.BCRYPT_SALT_ROUNDS);
  }

  /**
   * 비밀번호 검증
   */
  static async verifyPassword(
    password: string,
    hashedPassword: string,
  ): Promise<boolean> {
    return bcrypt.compare(password, hashedPassword);
  }

  /**
   * 비밀번호 강도 검증 (기본적인 검증)
   */
  static validatePasswordStrength(password: string): {
    isValid: boolean;
    message?: string;
  } {
    if (password.length < PASSWORD_VALIDATION.MIN_LENGTH) {
      return {
        isValid: false,
        message: PASSWORD_VALIDATION.ERRORS.TOO_SHORT,
      };
    }

    if (!PASSWORD_VALIDATION.LOWERCASE_PATTERN.test(password)) {
      return {
        isValid: false,
        message: PASSWORD_VALIDATION.ERRORS.NO_LOWERCASE,
      };
    }

    if (!PASSWORD_VALIDATION.UPPERCASE_PATTERN.test(password)) {
      return {
        isValid: false,
        message: PASSWORD_VALIDATION.ERRORS.NO_UPPERCASE,
      };
    }

    if (!PASSWORD_VALIDATION.DIGIT_PATTERN.test(password)) {
      return {
        isValid: false,
        message: PASSWORD_VALIDATION.ERRORS.NO_DIGIT,
      };
    }

    return { isValid: true };
  }
}
