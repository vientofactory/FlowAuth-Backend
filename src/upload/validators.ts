import type { MulterFile } from './types';
import { UPLOAD_CONFIG } from './config';

/**
 * 파일 업로드 검증 관련 상수들
 */
export const VALIDATION_CONSTANTS = {
  MAX_FILENAME_LENGTH: 255,
  FILENAME_PATTERN: /^[a-zA-Z0-9._-]+$/,
  FORBIDDEN_PATH_CHARS: ['..', '/', '\\'],
} as const;

/**
 * 파일 업로드 검증 에러들
 */
export class FileValidationError extends Error {
  constructor(
    message: string,
    public readonly code: string,
    public readonly field?: string,
  ) {
    super(message);
    this.name = 'FileValidationError';
  }
}

/**
 * 파일명 검증 결과
 */
export interface FilenameValidationResult {
  isValid: boolean;
  error?: string;
  sanitizedFilename?: string;
}

/**
 * 파일 검증 결과
 */
export interface FileValidationResult {
  isValid: boolean;
  errors: string[];
  warnings: string[];
}

/**
 * 파일 업로드 검증기 클래스
 */
export class FileUploadValidator {
  /**
   * 파일명 검증 (디렉토리 트래버설 및 보안 취약점 방지)
   */
  validateFilename(filename: string): FilenameValidationResult {
    try {
      // 빈 파일명 체크
      if (!filename || filename.trim().length === 0) {
        return {
          isValid: false,
          error: '파일명이 비어있습니다.',
        };
      }

      // 파일명 길이 체크
      if (filename.length > VALIDATION_CONSTANTS.MAX_FILENAME_LENGTH) {
        return {
          isValid: false,
          error: `파일명이 너무 깁니다. 최대 ${VALIDATION_CONSTANTS.MAX_FILENAME_LENGTH}자까지 허용됩니다.`,
        };
      }

      // 허용되지 않은 문자 패턴 체크
      if (!VALIDATION_CONSTANTS.FILENAME_PATTERN.test(filename)) {
        return {
          isValid: false,
          error:
            '파일명에 허용되지 않은 문자가 포함되어 있습니다. 영문, 숫자, 점(.), 밑줄(_), 하이픈(-)만 허용됩니다.',
        };
      }

      // 경로 트래버설 공격 방지
      for (const forbiddenChar of VALIDATION_CONSTANTS.FORBIDDEN_PATH_CHARS) {
        if (filename.includes(forbiddenChar)) {
          return {
            isValid: false,
            error: '파일명에 보안상 허용되지 않은 문자가 포함되어 있습니다.',
          };
        }
      }

      // 추가 보안 체크: 숨겨진 파일 방지
      if (filename.startsWith('.')) {
        return {
          isValid: false,
          error: '숨겨진 파일은 업로드할 수 없습니다.',
        };
      }

      return {
        isValid: true,
        sanitizedFilename: filename.trim(),
      };
    } catch {
      return {
        isValid: false,
        error: '파일명 검증 중 오류가 발생했습니다.',
      };
    }
  }

  /**
   * 파일 타입 검증
   */
  validateFileType(
    file: MulterFile,
    allowedTypes: readonly string[],
  ): { isValid: boolean; error?: string } {
    try {
      if (!file || !file.mimetype) {
        return {
          isValid: false,
          error: '파일 타입을 확인할 수 없습니다.',
        };
      }

      if (!allowedTypes.includes(file.mimetype)) {
        return {
          isValid: false,
          error: `허용되지 않은 파일 타입입니다. 허용 타입: ${allowedTypes.join(', ')}`,
        };
      }

      return { isValid: true };
    } catch {
      return {
        isValid: false,
        error: '파일 타입 검증 중 오류가 발생했습니다.',
      };
    }
  }

  /**
   * 파일 크기 검증
   */
  validateFileSize(
    file: MulterFile,
    maxSize: number,
  ): { isValid: boolean; error?: string } {
    try {
      // 파일 객체 존재 여부 및 size 속성 검증
      if (!file) {
        return {
          isValid: false,
          error: '파일 객체가 존재하지 않습니다.',
        };
      }

      // size 속성이 없거나 유효하지 않은 경우
      if (
        file.size === undefined ||
        file.size === null ||
        isNaN(file.size) ||
        typeof file.size !== 'number'
      ) {
        return {
          isValid: false,
          error: '파일 크기를 확인할 수 없습니다.',
        };
      }

      // 파일 크기가 음수인 경우
      if (file.size < 0) {
        return {
          isValid: false,
          error: '파일 크기가 유효하지 않습니다.',
        };
      }

      if (file.size > maxSize) {
        const maxSizeMB = Math.round((maxSize / (1024 * 1024)) * 100) / 100;
        const fileSizeMB = Math.round((file.size / (1024 * 1024)) * 100) / 100;

        return {
          isValid: false,
          error: `파일 크기가 너무 큽니다. 최대 ${maxSizeMB}MB까지 허용되며, 현재 파일은 ${fileSizeMB}MB입니다.`,
        };
      }

      if (file.size === 0) {
        return {
          isValid: false,
          error: '빈 파일은 업로드할 수 없습니다.',
        };
      }

      return { isValid: true };
    } catch {
      return {
        isValid: false,
        error: '파일 크기 검증 중 오류가 발생했습니다.',
      };
    }
  }

  /**
   * 파일 확장자 검증 (MIME 타입과 일치하는지 확인)
   */
  validateFileExtension(file: MulterFile): {
    isValid: boolean;
    error?: string;
    warning?: string;
  } {
    try {
      if (!file || !file.originalname || !file.mimetype) {
        return {
          isValid: false,
          error: '파일 정보를 확인할 수 없습니다.',
        };
      }

      const extension = file.originalname.split('.').pop()?.toLowerCase();
      if (!extension) {
        return {
          isValid: false,
          error: '파일 확장자를 확인할 수 없습니다.',
        };
      }

      // MIME 타입과 확장자의 일치성 검증
      const mimeToExtMap: Record<string, string[]> = {
        'image/jpeg': ['jpg', 'jpeg'],
        'image/png': ['png'],
        'image/webp': ['webp'],
        'image/gif': ['gif'],
        'image/svg+xml': ['svg'],
        'application/pdf': ['pdf'],
        'text/plain': ['txt'],
        'application/json': ['json'],
        'application/xml': ['xml'],
        'text/xml': ['xml'],
      };

      const expectedExtensions = mimeToExtMap[file.mimetype];
      if (expectedExtensions && !expectedExtensions.includes(extension)) {
        return {
          isValid: false,
          error: `파일 확장자(${extension})가 MIME 타입(${file.mimetype})과 일치하지 않습니다.`,
        };
      }

      return { isValid: true };
    } catch {
      return {
        isValid: false,
        error: '파일 확장자 검증 중 오류가 발생했습니다.',
      };
    }
  }

  /**
   * 종합 파일 검증 (타입, 크기, 확장자)
   */
  validateFile(
    file: MulterFile,
    type: keyof typeof UPLOAD_CONFIG.fileTypes,
    options: { skipSizeValidation?: boolean } = {},
  ): FileValidationResult {
    const result: FileValidationResult = {
      isValid: true,
      errors: [],
      warnings: [],
    };

    try {
      const config = UPLOAD_CONFIG.fileTypes[type];
      if (!config) {
        result.isValid = false;
        result.errors.push(`지원하지 않는 파일 타입입니다: ${type}`);
        return result;
      }

      // 파일 타입 검증
      const typeValidation = this.validateFileType(file, config.allowedMimes);
      if (!typeValidation.isValid) {
        result.isValid = false;
        result.errors.push(typeValidation.error!);
      }

      // 파일 크기 검증 (옵션에 따라 건너뜀)
      if (!options.skipSizeValidation) {
        const sizeValidation = this.validateFileSize(file, config.maxSize);
        if (!sizeValidation.isValid) {
          result.isValid = false;
          result.errors.push(sizeValidation.error!);
        }
      }

      // 파일 확장자 검증
      const extensionValidation = this.validateFileExtension(file);
      if (!extensionValidation.isValid) {
        result.isValid = false;
        result.errors.push(extensionValidation.error!);
      } else if (extensionValidation.warning) {
        result.warnings.push(extensionValidation.warning);
      }

      // 추가 검증 로직들 (필요시 확장)
      // 예: 바이러스 스캔, 이미지 유효성 검증 등

      return result;
    } catch {
      result.isValid = false;
      result.errors.push('파일 검증 중 오류가 발생했습니다.');
      return result;
    }
  }

  /**
   * 파일명 검증 헬퍼 함수 (간단 버전)
   */
  isValidFilename(filename: string): boolean {
    const result = this.validateFilename(filename);
    return result.isValid;
  }

  /**
   * 파일 검증 헬퍼 함수 (간단 버전)
   */
  isValidFile(
    file: MulterFile,
    type: keyof typeof UPLOAD_CONFIG.fileTypes,
  ): boolean {
    const result = this.validateFile(file, type);
    return result.isValid;
  }
}

/**
 * 기본 검증기 인스턴스
 */
export const fileUploadValidator = new FileUploadValidator();

/**
 * 편의 함수들 (기존 코드와의 호환성 유지)
 */
export function validateFilename(filename: string): FilenameValidationResult {
  return fileUploadValidator.validateFilename(filename);
}

export function validateFile(
  file: MulterFile,
  type: keyof typeof UPLOAD_CONFIG.fileTypes,
): FileValidationResult {
  return fileUploadValidator.validateFile(file, type);
}

export function isValidFilename(filename: string): boolean {
  return fileUploadValidator.isValidFilename(filename);
}

export function isValidFile(
  file: MulterFile,
  type: keyof typeof UPLOAD_CONFIG.fileTypes,
): boolean {
  return fileUploadValidator.isValidFile(file, type);
}
