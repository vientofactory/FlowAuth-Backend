/**
 * Content Type Security Utility (Refactored)
 *
 * Provides enhanced content type validation with optional buffer analysis.
 * Now uses a separate BufferAnalysisEngine that can be selectively disabled
 * to handle false positives and performance concerns.
 *
 * Features:
 * - Configurable buffer analysis engine
 * - MIME type spoofing detection with optional magic bytes validation
 * - Malicious file detection with pattern analysis controls
 * - Content validation for specific file types
 * - False positive mitigation through selective analysis
 *
 * @version 2.0.0
 */

import { Logger } from '@nestjs/common';
import {
  BufferAnalysisEngine,
  BufferAnalysisConfig,
  BufferAnalysisResult,
  getBufferAnalysisEngine,
} from './buffer-analysis.engine';
import {
  getSecurityRisk,
  SecurityRisk,
  isDangerousMimeType,
} from './magic-bytes-signatures';

/**
 * Enhanced security configuration for content validation
 */
export interface ContentSecurityConfig {
  allowedMimeTypes?: string[];
  blockedMimeTypes?: string[];
  maxFileSize?: number;
  enableBufferAnalysis?: boolean;
  bufferAnalysisConfig?: BufferAnalysisConfig;
  enableSpoofingDetection?: boolean;
  minSecurityScore?: number;
  maxSecurityScore?: number;
}

/**
 * Validation result for file content analysis
 */
export interface FileContentValidationResult {
  isValid: boolean;
  detectedMimeType: string | null;
  declaredMimeType: string;
  isSpoofed: boolean;
  securityScore: number;
  warnings: string[];
  errors: string[];
  bufferAnalysisResult?: BufferAnalysisResult;
}

/**
 * Default security configuration
 */
const DEFAULT_SECURITY_CONFIG: Required<ContentSecurityConfig> = {
  allowedMimeTypes: [
    'image/jpeg',
    'image/png',
    'image/gif',
    'image/webp',
    'image/svg+xml',
    'application/pdf',
    'text/plain',
    'application/json',
  ],
  blockedMimeTypes: [
    'application/x-msdownload',
    'application/x-executable',
    'application/x-mach-binary',
    'application/x-dosexec',
    'application/java-archive',
    'application/x-java-class',
  ],
  maxFileSize: 10 * 1024 * 1024, // 10MB
  enableBufferAnalysis: true,
  bufferAnalysisConfig: {},
  enableSpoofingDetection: true,
  minSecurityScore: 70,
  maxSecurityScore: 100,
};

/**
 * Content Type Security Validator (Refactored)
 *
 * Now uses a separate BufferAnalysisEngine for low-level analysis
 * while maintaining high-level security policy enforcement.
 */
export class ContentTypeSecurityValidator {
  private readonly config: Required<ContentSecurityConfig>;
  private readonly logger = new Logger(ContentTypeSecurityValidator.name);
  private readonly bufferEngine: BufferAnalysisEngine;

  constructor(config?: ContentSecurityConfig) {
    this.config = { ...DEFAULT_SECURITY_CONFIG, ...config };

    // Create a dedicated buffer analysis engine instance for this validator
    // This prevents global state conflicts between different validator instances
    this.bufferEngine = new BufferAnalysisEngine(
      this.config.bufferAnalysisConfig,
    );

    // Enable/disable buffer analysis based on configuration
    if (this.config.enableBufferAnalysis) {
      this.bufferEngine.enable();
    } else {
      this.bufferEngine.disable();
      // Silent operation - no logs during normal operation or bootstrap
    }
  }

  /**
   * Get current security configuration
   */
  getConfig(): Required<ContentSecurityConfig> {
    return { ...this.config };
  }

  /**
   * Enable buffer analysis engine
   */
  enableBufferAnalysis(): void {
    this.config.enableBufferAnalysis = true;
    this.bufferEngine.enable();

    // Double-check to ensure it's actually enabled
    if (!this.bufferEngine.isEnabled()) {
      this.logger.error(
        'Failed to enable buffer analysis engine, attempting force enable',
      );
      // Try enabling again
      this.bufferEngine.enable();
    }
  }

  /**
   * Disable buffer analysis engine (for handling false positives)
   */
  disableBufferAnalysis(): void {
    this.config.enableBufferAnalysis = false;
    this.bufferEngine.disable();
  }

  /**
   * Check if buffer analysis is enabled
   */
  isBufferAnalysisEnabled(): boolean {
    return this.config.enableBufferAnalysis && this.bufferEngine.isEnabled();
  }

  /**
   * Validate file content for enhanced security
   */
  validateFileContent(
    buffer: Buffer,
    filename: string,
    declaredMimeType: string,
  ): Promise<FileContentValidationResult> {
    try {
      let bufferAnalysisResult: BufferAnalysisResult;

      // Perform buffer analysis if enabled at instance level
      if (this.config.enableBufferAnalysis) {
        // Use the dedicated instance's buffer analysis engine
        if (this.bufferEngine.isEnabled()) {
          bufferAnalysisResult = this.bufferEngine.analyzeBuffer(
            buffer,
            filename,
          );
        } else {
          this.logger.error(
            'Buffer analysis engine could not be enabled, creating skipped result',
          );
          bufferAnalysisResult = {
            detectedMimeType: null,
            hasSuspiciousPatterns: false,
            suspiciousPatterns: [],
            confidence: 0,
            analysisSkipped: true,
            skipReason: 'Buffer analysis engine could not be enabled',
          };
        }
      } else {
        // Create a skipped result when disabled by configuration
        bufferAnalysisResult = {
          detectedMimeType: null,
          hasSuspiciousPatterns: false,
          suspiciousPatterns: [],
          confidence: 0,
          analysisSkipped: true,
          skipReason: 'Buffer analysis disabled by configuration',
        };
      }

      // Extract detected MIME type from buffer analysis
      const detectedMimeType = bufferAnalysisResult.detectedMimeType;

      // Check for spoofing - only flag as spoofed if we detect different type and analysis wasn't skipped
      const isSpoofed =
        this.config.enableSpoofingDetection &&
        detectedMimeType !== null &&
        detectedMimeType !== declaredMimeType &&
        !bufferAnalysisResult.analysisSkipped &&
        !this.isCompatibleMimeType(detectedMimeType, declaredMimeType);

      // Calculate security score
      const securityScore = this.calculateSecurityScore(
        buffer,
        filename,
        declaredMimeType,
        detectedMimeType,
        bufferAnalysisResult,
      );

      const result: FileContentValidationResult = {
        isValid: !isSpoofed && securityScore >= this.config.minSecurityScore,
        detectedMimeType,
        declaredMimeType,
        isSpoofed,
        securityScore,
        warnings: [],
        errors: [],
        bufferAnalysisResult,
      };

      // Add warnings and errors
      if (isSpoofed) {
        result.errors.push(
          `MIME type spoofing detected: declared ${declaredMimeType}, actual ${detectedMimeType}`,
        );
      }

      if (securityScore < this.config.minSecurityScore) {
        result.warnings.push(
          `Low security score: ${securityScore}/${this.config.maxSecurityScore}`,
        );
      }

      if (this.isDangerous(filename, declaredMimeType, detectedMimeType)) {
        result.errors.push('Dangerous file type detected');
      }

      // Add buffer analysis warnings
      if (bufferAnalysisResult.analysisSkipped) {
        result.warnings.push(
          `Buffer analysis skipped: ${bufferAnalysisResult.skipReason || 'Unknown reason'}`,
        );
      }

      if (bufferAnalysisResult.hasSuspiciousPatterns) {
        result.warnings.push(
          `Suspicious patterns detected: ${bufferAnalysisResult.suspiciousPatterns.join(', ')}`,
        );
      }

      this.logger.debug(
        `Content validation completed: ${JSON.stringify({
          ...result,
          bufferAnalysisResult: undefined, // Don't log the full buffer analysis result to reduce noise
        })}`,
      );

      return Promise.resolve(result);
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : 'Unknown error';
      const errorStack = error instanceof Error ? error.stack : undefined;

      this.logger.error(
        `Content validation failed: ${errorMessage}`,
        errorStack,
      );
      return Promise.resolve({
        isValid: false,
        detectedMimeType: null,
        declaredMimeType,
        isSpoofed: false,
        securityScore: 0,
        warnings: [],
        errors: [`Content validation failed: ${errorMessage}`],
      });
    }
  }

  /**
   * Check if two MIME types are compatible
   */
  private isCompatibleMimeType(detected: string, declared: string): boolean {
    // Handle common compatible MIME types
    const compatibilityMap: Record<string, string[]> = {
      'image/jpeg': ['image/jpg'],
      'image/jpg': ['image/jpeg'],
      'text/plain': ['text/plain; charset=utf-8'],
      'application/zip': [
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'application/vnd.openxmlformats-officedocument.presentationml.presentation',
      ],
    };

    // eslint-disable-next-line security/detect-object-injection
    const compatibleTypes = compatibilityMap[detected];
    return compatibleTypes ? compatibleTypes.includes(declared) : false;
  }

  /**
   * Calculate security score based on multiple factors including buffer analysis
   */
  private calculateSecurityScore(
    buffer: Buffer,
    filename: string,
    declaredMimeType: string,
    detectedMimeType: string | null,
    bufferAnalysisResult: BufferAnalysisResult,
  ): number {
    let score = this.config.maxSecurityScore;

    // Handle empty buffers
    if (buffer.length === 0) {
      return 0;
    }

    // Use new security risk classification system
    const declaredRisk = getSecurityRisk(declaredMimeType);
    const detectedRisk = detectedMimeType
      ? getSecurityRisk(detectedMimeType)
      : null;

    // Deduct points based on security risk level
    switch (declaredRisk) {
      case SecurityRisk.DANGEROUS:
        score -= 80; // 위험한 실행 파일들
        break;
      case SecurityRisk.SUSPICIOUS:
        score -= 30; // 잠재적 위험 (PDF, SVG, 아카이브 등)
        break;
      case SecurityRisk.BLOCKED:
        return 0; // 완전히 차단되어야 하는 파일
      case SecurityRisk.SAFE:
      default:
        // 안전한 파일은 점수 감점 없음
        break;
    }

    // Detected MIME type이 declared와 다르면 스푸핑 가능성
    if (detectedMimeType && detectedMimeType !== declaredMimeType) {
      score -= 20;

      // 더 위험한 타입으로 스푸핑된 경우 추가 감점
      if (detectedRisk === SecurityRisk.DANGEROUS) {
        score -= 50;
      } else if (detectedRisk === SecurityRisk.SUSPICIOUS) {
        score -= 20;
      }
    }

    if (!this.config.allowedMimeTypes.includes(declaredMimeType)) {
      score -= 15;
    }

    if (this.config.blockedMimeTypes.includes(declaredMimeType)) {
      score -= 40;
    }

    if (buffer.length > this.config.maxFileSize) {
      score -= 15;
    }

    // Use buffer analysis results for suspicious patterns
    if (bufferAnalysisResult.hasSuspiciousPatterns) {
      score -= 25;
    }

    // Reduce score based on buffer analysis confidence
    if (!bufferAnalysisResult.analysisSkipped) {
      const confidencePenalty = (100 - bufferAnalysisResult.confidence) * 0.1;
      score -= confidencePenalty;
    }

    return Math.max(0, score);
  }

  /**
   * Check if file is dangerous based on multiple criteria
   */
  private isDangerous(
    filename: string,
    declaredMimeType: string,
    detectedMimeType: string | null,
  ): boolean {
    // 파일 확장자 기반 위험 체크 (여전히 유용함)
    const dangerousExtensions = [
      '.exe',
      '.bat',
      '.cmd',
      '.com',
      '.scr',
      '.pif',
      '.jar',
      '.class',
      '.sh',
      '.bash',
      '.ps1',
      '.vbs',
      '.py',
    ];

    // Check file extension
    const hasDangerousExtension = dangerousExtensions.some((ext) =>
      filename.toLowerCase().endsWith(ext),
    );

    // Use new security classification system
    const declaredIsDangerous = isDangerousMimeType(declaredMimeType);
    const detectedIsDangerous = detectedMimeType
      ? isDangerousMimeType(detectedMimeType)
      : false;

    return hasDangerousExtension || declaredIsDangerous || detectedIsDangerous;
  }

  /**
   * Quick security check for file content
   */
  isFileContentSafe(
    buffer: Buffer,
    filename: string,
    declaredMimeType: string,
  ): boolean {
    try {
      let bufferAnalysisResult: BufferAnalysisResult;

      // Perform buffer analysis if enabled
      if (this.config.enableBufferAnalysis && this.bufferEngine.isEnabled()) {
        bufferAnalysisResult = this.bufferEngine.analyzeBuffer(
          buffer,
          filename,
        );
      } else {
        bufferAnalysisResult = {
          detectedMimeType: null,
          hasSuspiciousPatterns: false,
          suspiciousPatterns: [],
          confidence: 0,
          analysisSkipped: true,
          skipReason: 'Buffer analysis engine is disabled',
        };
      }

      const detectedMimeType = bufferAnalysisResult.detectedMimeType;

      // Check if dangerous file type
      if (this.isDangerous(filename, declaredMimeType, detectedMimeType)) {
        return false;
      }

      // Check for suspicious patterns from buffer analysis
      if (bufferAnalysisResult.hasSuspiciousPatterns) {
        return false;
      }

      return true;
    } catch (error) {
      this.logger.error(
        `Content safety check failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
      );
      return false;
    }
  }
}

/**
 * Enhanced content validation function with configurable buffer analysis
 */
export async function validateFileContent(
  buffer: Buffer,
  filename: string,
  declaredMimeType: string,
  config?: ContentSecurityConfig,
): Promise<FileContentValidationResult> {
  const validator = new ContentTypeSecurityValidator(config);
  return validator.validateFileContent(buffer, filename, declaredMimeType);
}

/**
 * Quick security check for file content using buffer analysis
 */
export function isFileContentSafe(
  buffer: Buffer,
  filename: string,
  declaredMimeType: string,
  enableBufferAnalysis = true,
): boolean {
  try {
    // Create a temporary instance instead of modifying global state
    const tempEngine = new BufferAnalysisEngine();

    if (enableBufferAnalysis) {
      tempEngine.enable();
    } else {
      tempEngine.disable();
    }

    const bufferAnalysisResult = tempEngine.analyzeBuffer(buffer, filename);
    const detectedMimeType = bufferAnalysisResult.detectedMimeType;

    // Check dangerous patterns manually since we can't access private methods
    const dangerousExtensions = [
      '.exe',
      '.bat',
      '.cmd',
      '.com',
      '.scr',
      '.pif',
      '.jar',
      '.class',
    ];
    const dangerousMimeTypes = [
      'application/x-msdownload',
      'application/x-executable',
      'application/x-mach-binary',
      'application/java-archive',
    ];

    // Check file extension
    const hasDangerousExtension = dangerousExtensions.some((ext) =>
      filename.toLowerCase().endsWith(ext),
    );

    // Check MIME types
    const hasDangerousDeclaredType =
      dangerousMimeTypes.includes(declaredMimeType);
    const hasDangerousDetectedType =
      detectedMimeType && dangerousMimeTypes.includes(detectedMimeType);

    const isDangerous =
      hasDangerousExtension ||
      hasDangerousDeclaredType ||
      Boolean(hasDangerousDetectedType);

    // Check for suspicious patterns from buffer analysis
    const hasSuspiciousPatterns = bufferAnalysisResult.hasSuspiciousPatterns;

    return !isDangerous && !hasSuspiciousPatterns;
  } catch {
    return false;
  }
}

/**
 * Get MIME type from file content using buffer analysis engine
 */
export function getMimeTypeFromContent(
  buffer: Buffer,
  enableBufferAnalysis = true,
): string | null {
  // Create a temporary instance instead of modifying global state
  const tempEngine = new BufferAnalysisEngine();

  if (enableBufferAnalysis) {
    tempEngine.enable();
  } else {
    tempEngine.disable();
  }

  const result = tempEngine.analyzeBuffer(buffer);
  return result.detectedMimeType;
}

/**
 * Utility functions for enabling/disabling buffer analysis globally
 */
export function enableBufferAnalysisGlobally(): void {
  const engine = getBufferAnalysisEngine();
  engine.enable();
}

export function disableBufferAnalysisGlobally(): void {
  const engine = getBufferAnalysisEngine();
  engine.disable();
}

export function isBufferAnalysisEnabledGlobally(): boolean {
  const engine = getBufferAnalysisEngine();
  return engine.isEnabled();
}
