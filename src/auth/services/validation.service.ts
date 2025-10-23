import { BadRequestException, Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from '../user.entity';
import {
  VALIDATION_CONSTANTS,
  type AvailabilityResult,
  type UrlValidationOptions,
} from '../../constants/validation.constants';

/**
 * 검증 서비스 클래스
 * 각종 검증 로직을 중앙집중화하여 관리
 */
@Injectable()
export class ValidationService {
  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
  ) {}

  /**
   * 이메일 가용성 체크
   */
  async checkEmailAvailability(email: string): Promise<AvailabilityResult> {
    // 입력 검증
    if (email?.trim().length === 0) {
      return {
        available: false,
        message: VALIDATION_CONSTANTS.EMAIL.ERROR_MESSAGES.REQUIRED,
      };
    }

    const trimmedEmail = email.trim();

    // 이메일 형식 검증
    if (!VALIDATION_CONSTANTS.EMAIL.REGEX.test(trimmedEmail)) {
      return {
        available: false,
        message: VALIDATION_CONSTANTS.EMAIL.ERROR_MESSAGES.INVALID_FORMAT,
      };
    }

    // 중복 체크
    const existingUser = await this.userRepository.findOne({
      where: { email: trimmedEmail },
    });

    if (existingUser) {
      return {
        available: false,
        message: VALIDATION_CONSTANTS.EMAIL.ERROR_MESSAGES.ALREADY_EXISTS,
      };
    }

    return {
      available: true,
      message: VALIDATION_CONSTANTS.EMAIL.ERROR_MESSAGES.AVAILABLE,
    };
  }

  /**
   * 사용자명 가용성 체크
   */
  async checkUsernameAvailability(
    username: string,
  ): Promise<AvailabilityResult> {
    // 입력 검증
    if (username?.trim().length === 0) {
      return {
        available: false,
        message: VALIDATION_CONSTANTS.USERNAME.ERROR_MESSAGES.REQUIRED,
      };
    }

    const trimmedUsername = username.trim();

    // 길이 검증
    if (trimmedUsername.length < VALIDATION_CONSTANTS.USERNAME.MIN_LENGTH) {
      return {
        available: false,
        message: VALIDATION_CONSTANTS.USERNAME.ERROR_MESSAGES.TOO_SHORT,
      };
    }

    if (trimmedUsername.length > VALIDATION_CONSTANTS.USERNAME.MAX_LENGTH) {
      return {
        available: false,
        message: VALIDATION_CONSTANTS.USERNAME.ERROR_MESSAGES.TOO_LONG,
      };
    }

    // 형식 검증
    if (!VALIDATION_CONSTANTS.USERNAME.REGEX.test(trimmedUsername)) {
      return {
        available: false,
        message: VALIDATION_CONSTANTS.USERNAME.ERROR_MESSAGES.INVALID_FORMAT,
      };
    }

    // 중복 체크
    const existingUser = await this.userRepository.findOne({
      where: { username: trimmedUsername },
    });

    if (existingUser) {
      return {
        available: false,
        message: VALIDATION_CONSTANTS.USERNAME.ERROR_MESSAGES.ALREADY_EXISTS,
      };
    }

    return {
      available: true,
      message: VALIDATION_CONSTANTS.USERNAME.ERROR_MESSAGES.AVAILABLE,
    };
  }

  /**
   * 이메일 형식 검증
   */
  static validateEmail(email: string): void {
    if (!VALIDATION_CONSTANTS.EMAIL.REGEX.test(email)) {
      throw new BadRequestException(
        VALIDATION_CONSTANTS.EMAIL.ERROR_MESSAGES.INVALID_FORMAT,
      );
    }
  }

  /**
   * 2FA 토큰 형식 검증
   */
  static validateTwoFactorToken(token: string): void {
    if (!VALIDATION_CONSTANTS.TWO_FACTOR_TOKEN.REGEX.test(token)) {
      throw new BadRequestException(
        VALIDATION_CONSTANTS.TWO_FACTOR_TOKEN.ERROR_MESSAGES.INVALID_FORMAT,
      );
    }
  }

  /**
   * 백업 코드 형식 검증
   */
  static validateBackupCode(code: string): void {
    if (!VALIDATION_CONSTANTS.BACKUP_CODE.REGEX.test(code.toUpperCase())) {
      throw new BadRequestException(
        VALIDATION_CONSTANTS.BACKUP_CODE.ERROR_MESSAGES.INVALID_FORMAT,
      );
    }
  }

  /**
   * URL 배열 검증
   */
  static validateUrlArray(
    urls: string[],
    fieldName: string = 'URL',
    options: UrlValidationOptions = {},
  ): void {
    if (!Array.isArray(urls)) {
      throw new BadRequestException(`${fieldName}는 배열이어야 합니다.`);
    }

    for (const url of urls) {
      if (typeof url !== 'string' || !url.trim()) {
        throw new BadRequestException(
          `${fieldName}의 각 항목은 비어있지 않은 문자열이어야 합니다.`,
        );
      }

      this.validateUrl(url.trim(), fieldName, options);
    }
  }

  /**
   * 단일 URL 검증
   */
  static validateUrl(
    url: string,
    fieldName: string = 'URL',
    options: UrlValidationOptions = {},
  ): void {
    try {
      const parsedUrl = new URL(url);

      // 프로토콜 검증
      if (options.allowedProtocols) {
        if (
          !options.allowedProtocols.includes(parsedUrl.protocol.slice(0, -1))
        ) {
          throw new BadRequestException(
            `${fieldName}는 ${options.allowedProtocols.join(', ')} 프로토콜만 허용됩니다.`,
          );
        }
      }

      // HTTPS 필수 검증
      if (options.requireHttps && parsedUrl.protocol !== 'https:') {
        throw new BadRequestException(
          `${fieldName}는 HTTPS 프로토콜을 사용해야 합니다.`,
        );
      }
    } catch (error) {
      if (error instanceof BadRequestException) {
        throw error;
      }
      throw new BadRequestException(`잘못된 ${fieldName} 형식: ${url}`);
    }
  }

  /**
   * 문자열 배열 검증
   */
  static validateStringArray(
    items: string[],
    fieldName: string,
    options: { minLength?: number; maxLength?: number } = {},
  ): void {
    if (!Array.isArray(items)) {
      throw new BadRequestException(`${fieldName}는 배열이어야 합니다.`);
    }

    for (const item of items) {
      if (typeof item !== 'string' || !item.trim()) {
        throw new BadRequestException(
          `${fieldName}의 각 항목은 비어있지 않은 문자열이어야 합니다.`,
        );
      }

      if (options.minLength && item.trim().length < options.minLength) {
        throw new BadRequestException(
          `${fieldName}의 각 항목은 최소 ${options.minLength}자 이상이어야 합니다.`,
        );
      }

      if (options.maxLength && item.trim().length > options.maxLength) {
        throw new BadRequestException(
          `${fieldName}의 각 항목은 최대 ${options.maxLength}자까지 가능합니다.`,
        );
      }
    }
  }

  /**
   * 필수 문자열 검증
   */
  static validateRequiredString(
    value: string | undefined,
    fieldName: string,
    options: { minLength?: number; maxLength?: number } = {},
  ): void {
    if (typeof value !== 'string' || !value.trim()) {
      throw new BadRequestException(
        `${fieldName}은 비어있지 않은 문자열이어야 합니다.`,
      );
    }

    const trimmedValue = value.trim();

    if (options.minLength && trimmedValue.length < options.minLength) {
      throw new BadRequestException(
        `${fieldName}은 최소 ${options.minLength}자 이상이어야 합니다.`,
      );
    }

    if (options.maxLength && trimmedValue.length > options.maxLength) {
      throw new BadRequestException(
        `${fieldName}은 최대 ${options.maxLength}자까지 가능합니다.`,
      );
    }
  }

  /**
   * ID 파라미터 검증
   */
  static validateIdParam(idParam: string): number {
    const id = parseInt(idParam, 10);
    if (isNaN(id) || id <= 0) {
      throw new BadRequestException(
        VALIDATION_CONSTANTS.GENERAL.ERROR_MESSAGES.INVALID_ID,
      );
    }
    return id;
  }
}
