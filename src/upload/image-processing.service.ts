import { Injectable, Logger } from '@nestjs/common';
import { existsSync, mkdirSync } from 'fs';
import { writeFile } from 'fs/promises';
import sharp from 'sharp';
import {
  safePath,
  validateFilename,
  sanitizeFilename,
} from '../utils/path-security.util';
import { v4 as uuidv4 } from 'uuid';
import { MulterFile, FileUploadError } from './types';
import { UPLOAD_CONFIG, getUploadPath } from './config';
import { DevelopmentLogger } from '../common/utils/development-logger.util';

@Injectable()
export class ImageProcessingService {
  private readonly logger = new Logger(ImageProcessingService.name);
  private readonly devLogger = new DevelopmentLogger(
    ImageProcessingService.name,
  );

  constructor() {
    this.ensureDirectoriesExist();
  }

  private ensureDirectoriesExist(): void {
    // Create directories for image types
    ['logo', 'avatar'].forEach((type) => {
      const path = getUploadPath(type as keyof typeof UPLOAD_CONFIG.fileTypes);
      // eslint-disable-next-line security/detect-non-literal-fs-filename
      if (!existsSync(path)) {
        // eslint-disable-next-line security/detect-non-literal-fs-filename
        mkdirSync(path, { recursive: true });
        this.devLogger.devLog(`Created image directory for ${type}: ${path}`);
      }
    });
  }

  /**
   * Process and save an image file with optimization
   * @param type - Image type ('logo' | 'avatar')
   * @param file - Uploaded file from multer
   * @param userId - User ID for avatar naming (optional)
   * @returns Promise<string> - URL of the processed image
   */
  async processAndSaveImage(
    type: 'logo' | 'avatar',
    file: MulterFile,
    userId?: number,
  ): Promise<string> {
    try {
      // Validate file type
      if (!file.mimetype.startsWith('image/')) {
        throw new FileUploadError(
          `Invalid file type for ${type}`,
          'INVALID_FILE_TYPE',
        );
      }

      // Validate file buffer
      if (
        !file.buffer ||
        !Buffer.isBuffer(file.buffer) ||
        file.buffer.length === 0
      ) {
        throw new FileUploadError(
          `Invalid or empty file buffer for ${type}`,
          'INVALID_FILE_BUFFER',
        );
      }

      // Generate unique filename using UUID
      const fileExtension =
        file.originalname.split('.').pop()?.toLowerCase() ?? '';
      const uniqueId = uuidv4();

      // Determine output format based on input and supported formats
      const outputFormat = this.determineOutputFormat(
        file.mimetype,
        fileExtension,
      );
      const outputExtension = this.getFormatExtension(outputFormat);

      const filename =
        type === 'avatar' && userId
          ? `${type}_${userId}_${uniqueId}.${outputExtension}`
          : `${type}_${uniqueId}.${outputExtension}`;

      // Process image with Sharp: resize and optimize for the determined format
      const processedBuffer = await this.processImageBuffer(
        file.buffer,
        outputFormat,
      );

      // Save processed file
      const destinationPath = getUploadPath(type);

      // Validate and sanitize filename
      if (!validateFilename(filename)) {
        throw new FileUploadError(
          'Invalid filename detected',
          'INVALID_FILENAME',
        );
      }

      const sanitizedFilename = sanitizeFilename(filename);
      const fullPath = safePath(sanitizedFilename, destinationPath);

      // Ensure destination directory exists with error handling
      try {
        // eslint-disable-next-line security/detect-non-literal-fs-filename
        if (!existsSync(destinationPath)) {
          // eslint-disable-next-line security/detect-non-literal-fs-filename
          mkdirSync(destinationPath, { recursive: true });
          this.devLogger.devLog(`Created directory: ${destinationPath}`);
        }
      } catch {
        throw new FileUploadError(
          `Failed to create upload directory: ${destinationPath}`,
          'DIRECTORY_CREATION_FAILED',
        );
      }

      // Save processed file with error handling
      try {
        // eslint-disable-next-line security/detect-non-literal-fs-filename
        await writeFile(fullPath, processedBuffer);
      } catch (error) {
        // Handle filesystem-specific errors
        if (error instanceof Error) {
          const errorMessage = error.message.toLowerCase();

          if (
            errorMessage.includes('enospc') ||
            errorMessage.includes('no space left')
          ) {
            throw new FileUploadError(
              'Insufficient disk space to save image',
              'INSUFFICIENT_DISK_SPACE',
            );
          }

          if (
            errorMessage.includes('eacces') ||
            errorMessage.includes('permission denied')
          ) {
            throw new FileUploadError(
              'Permission denied when saving image file',
              'PERMISSION_DENIED',
            );
          }

          if (
            errorMessage.includes('emfile') ||
            errorMessage.includes('too many open files')
          ) {
            throw new FileUploadError(
              'System file handle limit exceeded',
              'TOO_MANY_OPEN_FILES',
            );
          }
        }

        throw new FileUploadError(
          `Failed to save processed image file: ${error instanceof Error ? error.message : String(error)}`,
          'FILE_WRITE_FAILED',
        );
      }

      // Get file URL using the actual saved filename
      const imageUrl = this.getFileUrl(type, sanitizedFilename);

      this.devLogger.devLog(
        `${type.charAt(0).toUpperCase() + type.slice(1)} processed${
          userId ? ` for user ${userId}` : ''
        }: ${sanitizedFilename} (${processedBuffer.length} bytes)`,
      );
      return imageUrl;
    } catch (error) {
      // Re-throw FileUploadError instances as-is
      if (error instanceof FileUploadError) {
        this.logger.error(
          `Image processing error for ${type}: ${error.message}`,
          error.stack,
        );
        throw error;
      }

      // Handle Sharp-specific errors with detailed classification
      if (error instanceof Error) {
        const errorMessage = error.message.toLowerCase();

        if (
          errorMessage.includes('unsupported image format') ||
          errorMessage.includes('unknown file format')
        ) {
          this.logger.error(
            `Unsupported image format for ${type}: ${error.message}`,
            error.stack,
          );
          throw new FileUploadError(
            `Unsupported image format for ${type}. Please upload a valid image file.`,
            'UNSUPPORTED_FORMAT',
          );
        }

        if (
          errorMessage.includes('input image exceeds pixel limit') ||
          errorMessage.includes('limitInputPixels')
        ) {
          this.logger.error(
            `Image too large for ${type}: ${error.message}`,
            error.stack,
          );
          throw new FileUploadError(
            `Image too large to process for ${type} (exceeds pixel limit)`,
            'IMAGE_TOO_LARGE',
          );
        }

        if (
          errorMessage.includes('out of memory') ||
          errorMessage.includes('cannot allocate memory')
        ) {
          this.logger.error(
            `Memory allocation failed for ${type}: ${error.message}`,
            error.stack,
          );
          throw new FileUploadError(
            `Insufficient memory to process ${type} image`,
            'INSUFFICIENT_MEMORY',
          );
        }

        if (
          errorMessage.includes('invalid') ||
          errorMessage.includes('corrupt')
        ) {
          this.logger.error(
            `Corrupted image file for ${type}: ${error.message}`,
            error.stack,
          );
          throw new FileUploadError(
            `Image file appears to be corrupted or invalid for ${type}`,
            'CORRUPTED_IMAGE',
          );
        }
      }

      // Log and wrap unknown errors
      this.logger.error(
        `Unexpected error processing ${type} image: ${
          error instanceof Error ? error.message : String(error)
        }`,
        error instanceof Error ? error.stack : undefined,
      );
      throw new FileUploadError(
        `Failed to process ${type} image`,
        'PROCESS_FAILED',
      );
    }
  }

  /**
   * Process image buffer with Sharp using the specified output format
   */
  private async processImageBuffer(
    buffer: Buffer,
    outputFormat: keyof typeof UPLOAD_CONFIG.imageProcessing.formatOptions,
  ): Promise<Buffer> {
    try {
      // Validate buffer before processing
      if (!Buffer.isBuffer(buffer) || buffer.length === 0) {
        throw new FileUploadError(
          'Invalid or empty buffer provided for image processing',
          'INVALID_BUFFER',
        );
      }

      // Check buffer size limits to prevent memory issues
      const maxBufferSize = UPLOAD_CONFIG.imageProcessing.limits.maxBufferSize;
      if (buffer.length > maxBufferSize) {
        throw new FileUploadError(
          `Image buffer too large: ${buffer.length} bytes (max: ${maxBufferSize})`,
          'BUFFER_TOO_LARGE',
        );
      }

      const sharpInstance = sharp(buffer, {
        // Limit input format detection for security
        failOnError: false, // Don't fail on minor errors
        limitInputPixels: UPLOAD_CONFIG.imageProcessing.limits.maxInputPixels,
      });

      // Apply resize with error handling
      sharpInstance.resize(
        UPLOAD_CONFIG.imageProcessing.defaultSize.width,
        UPLOAD_CONFIG.imageProcessing.defaultSize.height,
        UPLOAD_CONFIG.imageProcessing.resizeOptions,
      );

      // Apply format-specific options with type safety
      switch (outputFormat) {
        case 'jpeg':
          sharpInstance.jpeg(UPLOAD_CONFIG.imageProcessing.formatOptions.jpeg);
          break;
        case 'png':
          sharpInstance.png(UPLOAD_CONFIG.imageProcessing.formatOptions.png);
          break;
        case 'webp':
          sharpInstance.webp(UPLOAD_CONFIG.imageProcessing.formatOptions.webp);
          break;
        case 'avif':
          sharpInstance.avif(UPLOAD_CONFIG.imageProcessing.formatOptions.avif);
          break;
        default:
          // Fallback to JPEG
          sharpInstance.jpeg(UPLOAD_CONFIG.imageProcessing.formatOptions.jpeg);
      }

      const processedBuffer = await sharpInstance.toBuffer();

      // Validate output buffer
      if (processedBuffer?.length === 0) {
        throw new FileUploadError(
          'Image processing resulted in empty buffer',
          'EMPTY_OUTPUT_BUFFER',
        );
      }

      return processedBuffer;
    } catch (error) {
      // Handle Sharp-specific errors with detailed classification
      if (error instanceof Error) {
        const errorMessage = error.message.toLowerCase();

        if (
          errorMessage.includes('unsupported image format') ||
          errorMessage.includes('unknown file format')
        ) {
          throw new FileUploadError(
            `Unsupported image format for ${outputFormat} conversion`,
            'UNSUPPORTED_FORMAT',
          );
        }

        if (
          errorMessage.includes('input image exceeds pixel limit') ||
          errorMessage.includes('limitInputPixels')
        ) {
          throw new FileUploadError(
            'Image too large to process (exceeds pixel limit)',
            'IMAGE_TOO_LARGE',
          );
        }

        if (
          errorMessage.includes('out of memory') ||
          errorMessage.includes('cannot allocate memory')
        ) {
          throw new FileUploadError(
            'Insufficient memory to process image',
            'INSUFFICIENT_MEMORY',
          );
        }

        if (
          errorMessage.includes('invalid') ||
          errorMessage.includes('corrupt')
        ) {
          throw new FileUploadError(
            'Image file appears to be corrupted or invalid',
            'CORRUPTED_IMAGE',
          );
        }
      }

      // Re-throw FileUploadError instances as-is
      if (error instanceof FileUploadError) {
        throw error;
      }

      // Wrap unknown errors
      throw new FileUploadError(
        `Image processing failed: ${error instanceof Error ? error.message : String(error)}`,
        'PROCESSING_FAILED',
      );
    }
  }

  /**
   * Determine the best output format based on input MIME type and supported formats
   */
  private determineOutputFormat(
    mimeType: string,
    fileExtension: string,
  ): keyof typeof UPLOAD_CONFIG.imageProcessing.formatOptions {
    // Map common MIME types to format names
    const mimeToFormat: Record<
      string,
      keyof typeof UPLOAD_CONFIG.imageProcessing.formatOptions
    > = {
      'image/jpeg': 'jpeg',
      'image/jpg': 'jpeg',
      'image/png': 'png',
      'image/webp': 'webp',
      'image/avif': 'avif',
      'image/gif': 'webp', // Convert GIF to WebP for better compression
      'image/bmp': 'jpeg', // Convert BMP to JPEG
      'image/tiff': 'jpeg', // Convert TIFF to JPEG
    };

    // Try to determine format from MIME type first using Map for type safety
    const mimeToFormatMap = new Map(Object.entries(mimeToFormat));
    const formatFromMime = mimeToFormatMap.get(mimeType);

    // If MIME type gives us a supported format, use it
    if (
      formatFromMime &&
      UPLOAD_CONFIG.imageProcessing.outputFormats.includes(formatFromMime)
    ) {
      return formatFromMime;
    }

    // Fallback to extension-based detection
    const extensionToFormat: Record<
      string,
      keyof typeof UPLOAD_CONFIG.imageProcessing.formatOptions
    > = {
      jpg: 'jpeg',
      jpeg: 'jpeg',
      png: 'png',
      webp: 'webp',
      avif: 'avif',
      gif: 'webp',
      bmp: 'jpeg',
      tiff: 'jpeg',
      tif: 'jpeg',
    };

    // Use Map for type-safe extension lookup
    const extensionToFormatMap = new Map(Object.entries(extensionToFormat));
    const formatFromExtension = extensionToFormatMap.get(fileExtension);

    // If extension gives us a supported format, use it
    if (
      formatFromExtension &&
      UPLOAD_CONFIG.imageProcessing.outputFormats.includes(formatFromExtension)
    ) {
      return formatFromExtension;
    }

    // Default to JPEG as fallback
    return 'jpeg';
  }

  /**
   * Get file extension for a given format
   */
  private getFormatExtension(
    format: keyof typeof UPLOAD_CONFIG.imageProcessing.formatOptions,
  ): string {
    const extensionMap: Record<
      keyof typeof UPLOAD_CONFIG.imageProcessing.formatOptions,
      string
    > = {
      jpeg: 'jpg',
      png: 'png',
      webp: 'webp',
      avif: 'avif',
    };

    // Use Map for type-safe format extension lookup
    const extensionMapObj = new Map(Object.entries(extensionMap));
    return extensionMapObj.get(format) ?? 'jpg';
  }

  /**
   * Get file URL for a specific type and filename
   */
  private getFileUrl(
    type: keyof typeof UPLOAD_CONFIG.fileTypes,
    filename: string,
  ): string {
    // Use type-safe config access
    const fileTypesMap = new Map(Object.entries(UPLOAD_CONFIG.fileTypes));
    const config = fileTypesMap.get(type);
    if (!config) {
      throw new Error(`Invalid file type: ${type}`);
    }
    return `/uploads/${config.destination}/${filename}`;
  }
}
