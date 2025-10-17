import { join } from 'path';
import { FILE_TYPES } from './types';
import {
  safePath,
  validateFilename,
  sanitizeFilename,
} from '../utils/path-security.util';

// File size constants (in bytes)
export const FILE_SIZE_LIMITS = {
  IMAGE: 1 * 1024 * 1024, // 1MB
  DOCUMENT: 5 * 1024 * 1024, // 5MB
  AVATAR: 1 * 1024 * 1024, // 1MB
  LOGO: 1 * 1024 * 1024, // 1MB
} as const;

// Upload configuration
export const UPLOAD_CONFIG = {
  // Base paths
  baseUploadPath: join(process.cwd(), 'uploads'),

  // File type specific configurations
  fileTypes: {
    logo: {
      ...FILE_TYPES.IMAGE,
      destination: 'logos',
      maxSize: FILE_SIZE_LIMITS.LOGO,
    },
    avatar: {
      ...FILE_TYPES.IMAGE,
      destination: 'avatars',
      maxSize: FILE_SIZE_LIMITS.AVATAR,
    },
    document: {
      ...FILE_TYPES.DOCUMENT,
      destination: 'documents',
      maxSize: FILE_SIZE_LIMITS.DOCUMENT,
    },
  },

  // Global upload settings
  global: {
    // Create directories if they don't exist
    createDirectories: true,

    // File naming strategy
    namingStrategy: 'uuid', // 'uuid' | 'timestamp' | 'original'

    // Security settings
    security: {
      // Remove potentially dangerous file extensions
      sanitizeFilename: true,

      // Check file content (magic bytes) in addition to mimetype
      validateContent: true,
    },

    // Performance settings
    performance: {
      // Use streaming for large files
      useStreaming: true,

      // Buffer size for streaming
      bufferSize: 64 * 1024, // 64KB
    },
  },

  // Cache settings for static file serving
  cache: {
    maxAge: 31536000, // 1 year in seconds
    cacheControl: 'public, max-age=31536000',
  },

  // Image processing settings
  imageProcessing: {
    // Sharp processing limits
    limits: {
      maxBufferSize: 50 * 1024 * 1024, // 50MB limit for buffer processing
      maxInputPixels: 50 * 1024 * 1024, // 50MP limit for input image pixels
    },

    // Default resize dimensions for avatars and logos
    defaultSize: {
      width: 256,
      height: 256,
    },

    // Resize options
    resizeOptions: {
      fit: 'cover' as const,
      position: 'center' as const,
    },

    // Output format priority (most optimized first)
    outputFormats: ['webp', 'avif', 'jpeg', 'png'] as const,

    // Format-specific optimization settings
    formatOptions: {
      jpeg: {
        quality: 85,
        mozjpeg: true,
      } as const,
      png: {
        compressionLevel: 9,
      } as const,
      webp: {
        quality: 85,
        effort: 6,
      } as const,
      avif: {
        quality: 80,
        effort: 6,
      } as const,
    } as const,

    // Legacy options for backward compatibility
    jpegOptions: {
      quality: 85,
      mozjpeg: true,
    },
    pngOptions: {
      compressionLevel: 9,
    },
  },
} as const;

// Helper functions
export const getUploadPath = (
  type: keyof typeof UPLOAD_CONFIG.fileTypes,
): string => {
  // Safe object access to prevent injection
  // eslint-disable-next-line security/detect-object-injection
  const fileTypeConfig = UPLOAD_CONFIG.fileTypes[type];
  if (!fileTypeConfig) {
    throw new Error(`Invalid file type: ${type}`);
  }

  // Use safePath to prevent path traversal attacks
  try {
    return safePath(fileTypeConfig.destination, UPLOAD_CONFIG.baseUploadPath);
  } catch (error) {
    throw new Error(
      `Invalid upload path configuration for ${type}: ${error instanceof Error ? error.message : 'Unknown error'}`,
    );
  }
};

export const getFileUrl = (
  type: keyof typeof UPLOAD_CONFIG.fileTypes,
  filename: string,
): string => {
  // eslint-disable-next-line security/detect-object-injection
  const fileTypeConfig = UPLOAD_CONFIG.fileTypes[type];
  if (!fileTypeConfig) {
    throw new Error(`Invalid file type: ${type}`);
  }
  const destination = fileTypeConfig.destination;
  // 백엔드 서버의 호스트를 포함한 절대 URL 반환
  const backendHost = process.env.BACKEND_HOST || 'http://localhost:3000';
  return `${backendHost}/uploads/${destination}/${filename}`;
};

export const getFileLimits = (type: keyof typeof UPLOAD_CONFIG.fileTypes) => {
  // eslint-disable-next-line security/detect-object-injection
  const config = UPLOAD_CONFIG.fileTypes[type];
  if (!config) {
    throw new Error(`Invalid file type: ${type}`);
  }
  return {
    fileSize: config.maxSize,
    files: 1,
  };
};

/**
 * Safely validate and sanitize uploaded filename
 * Prevents path traversal and malicious filename attacks
 */
export const validateAndSanitizeFilename = (filename: string): string => {
  if (!filename || typeof filename !== 'string') {
    throw new Error('Invalid filename: Must be a non-empty string');
  }

  // First, check if the original filename is valid
  if (!validateFilename(filename)) {
    // If not valid, sanitize it
    const sanitized = sanitizeFilename(filename);
    if (!sanitized) {
      throw new Error('Invalid filename: Cannot be sanitized to a safe name');
    }
    return sanitized;
  }

  return filename;
};

/**
 * Create a secure file path for uploaded files
 * Combines safe path resolution with filename validation
 */
export const createSecureFilePath = (
  type: keyof typeof UPLOAD_CONFIG.fileTypes,
  filename: string,
): string => {
  // Validate and sanitize filename first
  const safeFilename = validateAndSanitizeFilename(filename);

  // Get the secure upload path
  const uploadPath = getUploadPath(type);

  // Create the final secure path
  try {
    return safePath(safeFilename, uploadPath);
  } catch (error) {
    throw new Error(
      `Cannot create secure file path: ${error instanceof Error ? error.message : 'Unknown error'}`,
    );
  }
};
