/**
 * File Upload Validation Module
 *
 * This module provides various security validations required for file uploads:
 * - Filename security validation (integrated with path-security module)
 * - File type and size validation
 * - Path traversal attack prevention
 * - Safe file path generation
 *
 * @version 2.0.0 - path-security module integration
 */

import type { MulterFile } from './types';
import { UPLOAD_CONFIG } from './config';
import {
  validateFilename as validateFilenameSecure,
  sanitizeFilename,
  validatePathInput,
  safePath,
} from '../utils/path-security.util';

/**
 * File upload validation constants (integrated with path-security module)
 */
export const VALIDATION_CONSTANTS = {
  MAX_FILENAME_LENGTH: 255,
  FILENAME_PATTERN: /^[a-zA-Z0-9._-]+$/,
  FORBIDDEN_PATH_CHARS: ['..', '/', '\\'],
  // Security settings added from path-security module
  SECURITY_ENABLED: true,
  USE_PATH_SANITIZATION: true,
  ALLOW_UNICODE_NORMALIZATION: false,
} as const;

/**
 * File upload validation errors
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
 * Filename validation result
 */
export interface FilenameValidationResult {
  isValid: boolean;
  error?: string;
  sanitizedFilename?: string;
}

/**
 * File validation result
 */
export interface FileValidationResult {
  isValid: boolean;
  errors: string[];
  warnings: string[];
}

/**
 * File upload validator class
 */
export class FileUploadValidator {
  /**
   * Filename validation (prevents directory traversal and security vulnerabilities)
   * Enhanced validation using path-security module
   */
  validateFilename(filename: string): FilenameValidationResult {
    try {
      // Check for empty filename
      if (!filename || filename.trim().length === 0) {
        return {
          isValid: false,
          error: 'Filename is empty.',
        };
      }

      // Check filename length
      if (filename.length > VALIDATION_CONSTANTS.MAX_FILENAME_LENGTH) {
        return {
          isValid: false,
          error: `Filename is too long. Maximum ${VALIDATION_CONSTANTS.MAX_FILENAME_LENGTH} characters allowed.`,
        };
      }

      // Prevent path traversal attacks (priority check)
      for (const forbiddenChar of VALIDATION_CONSTANTS.FORBIDDEN_PATH_CHARS) {
        if (filename.includes(forbiddenChar)) {
          return {
            isValid: false,
            error: 'Filename contains security-forbidden characters.',
          };
        }
      }

      // Additional security check: prevent hidden files
      if (filename.startsWith('.')) {
        return {
          isValid: false,
          error: 'Hidden files cannot be uploaded.',
        };
      }

      // Advanced filename validation using path-security module
      if (!validateFilenameSecure(filename)) {
        return {
          isValid: false,
          error: 'Filename contains security-forbidden characters or patterns.',
        };
      }

      // Additional path input validation
      if (!validatePathInput(filename)) {
        return {
          isValid: false,
          error: 'Filename violates security policy.',
        };
      }

      // Check for disallowed character patterns (additional security layer)
      if (!VALIDATION_CONSTANTS.FILENAME_PATTERN.test(filename)) {
        return {
          isValid: false,
          error:
            'Filename contains disallowed characters. Only letters, numbers, dots (.), underscores (_), and hyphens (-) are allowed.',
        };
      }

      // Filename sanitization and validation
      const sanitizedFilename = sanitizeFilename(filename);
      if (!sanitizedFilename || sanitizedFilename !== filename) {
        return {
          isValid: false,
          error:
            'Filename does not comply with security policy and needs modification.',
          sanitizedFilename,
        };
      }

      return {
        isValid: true,
        sanitizedFilename: filename.trim(),
      };
    } catch (error) {
      return {
        isValid: false,
        error: `Error occurred during filename validation: ${error instanceof Error ? error.message : 'Unknown error'}`,
      };
    }
  }

  /**
   * Safe file path generation (utilizing path-security module)
   */
  createSafePath(
    filename: string,
    baseDirectory: string,
    subdirectory?: string,
  ): { success: boolean; path?: string; error?: string } {
    try {
      // Filename validation
      const filenameValidation = this.validateFilename(filename);
      if (!filenameValidation.isValid) {
        return {
          success: false,
          error: filenameValidation.error,
        };
      }

      const safeFilename = filenameValidation.sanitizedFilename!;
      let targetPath: string;

      if (subdirectory) {
        // Subdirectory validation
        if (!validatePathInput(subdirectory)) {
          return {
            success: false,
            error: 'Subdirectory name violates security policy.',
          };
        }

        const sanitizedSubdir = sanitizeFilename(subdirectory);
        const subdirPath = safePath(sanitizedSubdir, baseDirectory);
        targetPath = safePath(safeFilename, subdirPath);
      } else {
        targetPath = safePath(safeFilename, baseDirectory);
      }

      return {
        success: true,
        path: targetPath,
      };
    } catch (error) {
      return {
        success: false,
        error: `Safe path generation failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
      };
    }
  }

  /**
   * File type validation
   */
  validateFileType(
    file: MulterFile,
    allowedTypes: readonly string[],
  ): { isValid: boolean; error?: string } {
    try {
      if (!file || !file.mimetype) {
        return {
          isValid: false,
          error: 'File type cannot be determined.',
        };
      }

      if (!allowedTypes.includes(file.mimetype)) {
        return {
          isValid: false,
          error: `File type not allowed. Allowed types: ${allowedTypes.join(', ')}`,
        };
      }

      return { isValid: true };
    } catch {
      return {
        isValid: false,
        error: 'Error occurred during file type validation.',
      };
    }
  }

  /**
   * File size validation
   */
  validateFileSize(
    file: MulterFile,
    maxSize: number,
  ): { isValid: boolean; error?: string } {
    try {
      // Check file object existence and size property validation
      if (!file) {
        return {
          isValid: false,
          error: 'File object does not exist.',
        };
      }

      // Check if size property is missing or invalid
      if (
        file.size === undefined ||
        file.size === null ||
        isNaN(file.size) ||
        typeof file.size !== 'number'
      ) {
        return {
          isValid: false,
          error: 'File size cannot be determined.',
        };
      }

      // Check if file size is negative
      if (file.size < 0) {
        return {
          isValid: false,
          error: 'File size is invalid.',
        };
      }

      if (file.size > maxSize) {
        const maxSizeMB = Math.round((maxSize / (1024 * 1024)) * 100) / 100;
        const fileSizeMB = Math.round((file.size / (1024 * 1024)) * 100) / 100;

        return {
          isValid: false,
          error: `File size is too large. Maximum ${maxSizeMB}MB allowed, current file is ${fileSizeMB}MB.`,
        };
      }

      if (file.size === 0) {
        return {
          isValid: false,
          error: 'Empty files cannot be uploaded.',
        };
      }

      return { isValid: true };
    } catch {
      return {
        isValid: false,
        error: 'Error occurred during file size validation.',
      };
    }
  }

  /**
   * File extension validation (check if it matches MIME type)
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
          error: 'File information cannot be determined.',
        };
      }

      const extension = file.originalname.split('.').pop()?.toLowerCase();
      if (!extension) {
        return {
          isValid: false,
          error: 'File extension cannot be determined.',
        };
      }

      // Validation of MIME type and extension consistency
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
          error: `File extension (${extension}) does not match MIME type (${file.mimetype}).`,
        };
      }

      return { isValid: true };
    } catch {
      return {
        isValid: false,
        error: 'Error occurred during file extension validation.',
      };
    }
  }

  /**
   * Comprehensive file validation (type, size, extension, path security)
   */
  validateFile(
    file: MulterFile,
    type: keyof typeof UPLOAD_CONFIG.fileTypes,
    options: { skipSizeValidation?: boolean; baseDirectory?: string } = {},
  ): FileValidationResult {
    const result: FileValidationResult = {
      isValid: true,
      errors: [],
      warnings: [],
    };

    try {
      // eslint-disable-next-line security/detect-object-injection
      const config = UPLOAD_CONFIG.fileTypes[type];
      if (!config) {
        result.isValid = false;
        result.errors.push(`Unsupported file type: ${type}`);
        return result;
      }

      // Enhanced filename security validation
      if (file.originalname) {
        const filenameValidation = this.validateFilename(file.originalname);
        if (!filenameValidation.isValid) {
          result.isValid = false;
          result.errors.push(filenameValidation.error!);
        } else if (filenameValidation.sanitizedFilename !== file.originalname) {
          result.warnings.push(
            `Filename may be modified for security: ${filenameValidation.sanitizedFilename}`,
          );
        }
      }

      // Safe path generation validation (when baseDirectory is provided)
      if (options.baseDirectory && file.originalname) {
        const pathResult = this.createSafePath(
          file.originalname,
          options.baseDirectory,
        );
        if (!pathResult.success) {
          result.isValid = false;
          result.errors.push(pathResult.error!);
        }
      }

      // File type validation
      const typeValidation = this.validateFileType(file, config.allowedMimes);
      if (!typeValidation.isValid) {
        result.isValid = false;
        result.errors.push(typeValidation.error!);
      }

      // File size validation (skipped based on options)
      if (!options.skipSizeValidation) {
        const sizeValidation = this.validateFileSize(file, config.maxSize);
        if (!sizeValidation.isValid) {
          result.isValid = false;
          result.errors.push(sizeValidation.error!);
        }
      }

      // File extension validation
      const extensionValidation = this.validateFileExtension(file);
      if (!extensionValidation.isValid) {
        result.isValid = false;
        result.errors.push(extensionValidation.error!);
      } else if (extensionValidation.warning) {
        result.warnings.push(extensionValidation.warning);
      }

      // Additional validation logic (expandable as needed)
      // Example: virus scanning, image validity verification, etc.

      return result;
    } catch (error) {
      result.isValid = false;
      result.errors.push(
        `Error occurred during file validation: ${error instanceof Error ? error.message : 'Unknown error'}`,
      );
      return result;
    }
  }

  /**
   * Filename validation helper function (simple version)
   */
  isValidFilename(filename: string): boolean {
    const result = this.validateFilename(filename);
    return result.isValid;
  }

  /**
   * File validation helper function (simple version)
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
 * Default validator instance
 */
export const fileUploadValidator = new FileUploadValidator();

/**
 * Convenience functions (maintaining compatibility with existing code)
 */
export function validateFilename(filename: string): FilenameValidationResult {
  return fileUploadValidator.validateFilename(filename);
}

export function validateFile(
  file: MulterFile,
  type: keyof typeof UPLOAD_CONFIG.fileTypes,
  options?: { skipSizeValidation?: boolean; baseDirectory?: string },
): FileValidationResult {
  return fileUploadValidator.validateFile(file, type, options);
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

/**
 * New convenience functions (path security features)
 */
export function createSafeFilePath(
  filename: string,
  baseDirectory: string,
  subdirectory?: string,
): { success: boolean; path?: string; error?: string } {
  return fileUploadValidator.createSafePath(
    filename,
    baseDirectory,
    subdirectory,
  );
}

export function sanitizeAndValidateFilename(filename: string): {
  isValid: boolean;
  sanitized: string;
  error?: string;
} {
  try {
    const validation = fileUploadValidator.validateFilename(filename);
    const sanitized = sanitizeFilename(filename);

    return {
      isValid: validation.isValid,
      sanitized,
      error: validation.error,
    };
  } catch (error) {
    return {
      isValid: false,
      sanitized: sanitizeFilename(filename),
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}
