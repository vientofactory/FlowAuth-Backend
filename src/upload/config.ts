import { join } from 'path';
import { FILE_TYPES } from './types';

// Upload configuration
export const UPLOAD_CONFIG = {
  // Base paths
  baseUploadPath: join(process.cwd(), 'uploads'),

  // File type specific configurations
  fileTypes: {
    logo: {
      ...FILE_TYPES.IMAGE,
      destination: 'logos',
      maxSize: 1 * 1024 * 1024, // 1MB
    },
    avatar: {
      ...FILE_TYPES.IMAGE,
      destination: 'avatars',
      maxSize: 1 * 1024 * 1024, // 1MB
    },
    document: {
      ...FILE_TYPES.DOCUMENT,
      destination: 'documents',
      maxSize: 5 * 1024 * 1024, // 5MB
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
  return join(
    UPLOAD_CONFIG.baseUploadPath,
    UPLOAD_CONFIG.fileTypes[type].destination,
  );
};

export const getFileUrl = (
  type: keyof typeof UPLOAD_CONFIG.fileTypes,
  filename: string,
): string => {
  const destination = UPLOAD_CONFIG.fileTypes[type].destination;
  // 백엔드 서버의 호스트를 포함한 절대 URL 반환
  const backendHost = process.env.BACKEND_HOST || 'http://localhost:3000';
  return `${backendHost}/uploads/${destination}/${filename}`;
};

export const getFileLimits = (type: keyof typeof UPLOAD_CONFIG.fileTypes) => {
  const config = UPLOAD_CONFIG.fileTypes[type];
  return {
    fileSize: config.maxSize,
    files: 1,
  };
};
