import type { Request } from 'express';

// Core file upload types
export interface MulterFile {
  fieldname: string;
  originalname: string;
  encoding: string;
  mimetype: string;
  size: number;
  destination: string;
  filename: string;
  path: string;
  buffer: Buffer;
}

export interface UploadedFile {
  filename: string;
  originalname: string;
  mimetype: string;
  size: number;
  path: string;
  url: string;
}

// Upload configuration types
export interface FileUploadOptions {
  maxSize: number;
  allowedMimes: readonly string[];
  destination: string;
}

export interface UploadLimits {
  fileSize: number;
  files?: number;
}

// Response types
export interface UploadResponse {
  success: boolean;
  message: string;
  data: {
    filename: string;
    url: string;
    originalName: string;
    size: number;
    mimetype: string;
  };
}

export interface FileInfo {
  url: string;
  message: string;
}

// Multer callback types for type safety
export type MulterDestinationCallback = (
  error: Error | null,
  destination: string,
) => void;
export type MulterFilenameCallback = (
  error: Error | null,
  filename: string,
) => void;
export type MulterFileFilterCallback = (
  error: Error | null,
  acceptFile: boolean,
) => void;

// File type configurations
export const FILE_TYPES = {
  IMAGE: {
    allowedMimes: [
      'image/jpeg',
      'image/jpg',
      'image/png',
      'image/webp',
      'image/svg+xml',
    ] as const,
    maxSize: 5 * 1024 * 1024, // 5MB
  },
  DOCUMENT: {
    allowedMimes: [
      'application/pdf',
      'application/msword',
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      'text/plain',
    ] as const,
    maxSize: 10 * 1024 * 1024, // 10MB
  },
} as const;

// Error types
export class FileUploadError extends Error {
  constructor(
    message: string,
    public readonly code: string,
    public readonly statusCode: number = 400,
  ) {
    super(message);
    this.name = 'FileUploadError';
  }
}

export const UPLOAD_ERRORS = {
  FILE_TOO_LARGE: new FileUploadError(
    'File size exceeds limit',
    'FILE_TOO_LARGE',
    413,
  ),
  INVALID_FILE_TYPE: new FileUploadError(
    'Invalid file type',
    'INVALID_FILE_TYPE',
    400,
  ),
  FILE_NOT_FOUND: new FileUploadError('File not found', 'FILE_NOT_FOUND', 404),
  UPLOAD_FAILED: new FileUploadError(
    'File upload failed',
    'UPLOAD_FAILED',
    500,
  ),
  NO_FILE_UPLOADED: new FileUploadError(
    'No file uploaded',
    'NO_FILE_UPLOADED',
    400,
  ),
} as const;
