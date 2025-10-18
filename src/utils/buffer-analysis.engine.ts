/**
 * Buffer Analysis Engine
 *
 * Provides low-level buffer analysis capabilities for file content inspection.
 * This engine can be selectively enabled/disabled to handle false positives
 * and performance concerns.
 *
 * Features:
 * - Magic bytes detection
 * - MIME type identification from binary content
 * - Suspicious pattern analysis
 * - Configurable analysis depth
 *
 * @version 1.0.0
 */

import { Logger } from '@nestjs/common';
import { MAGIC_BYTES_SIGNATURES } from './magic-bytes-signatures';

/**
 * Configuration for buffer analysis engine
 */
export interface BufferAnalysisConfig {
  enableMagicBytesDetection?: boolean;
  enableSuspiciousPatternAnalysis?: boolean;
  maxAnalysisDepth?: number;
  skipLargeFiles?: boolean;
  maxFileSize?: number;
}

/**
 * Result of buffer analysis
 */
export interface BufferAnalysisResult {
  detectedMimeType: string | null;
  hasSuspiciousPatterns: boolean;
  suspiciousPatterns: string[];
  confidence: number;
  analysisSkipped: boolean;
  skipReason?: string;
}

/**
 * Default configuration for buffer analysis
 */
const DEFAULT_BUFFER_ANALYSIS_CONFIG: Required<BufferAnalysisConfig> = {
  enableMagicBytesDetection: true,
  enableSuspiciousPatternAnalysis: true,
  maxAnalysisDepth: 1024 * 1024, // 1MB
  skipLargeFiles: true,
  maxFileSize: 50 * 1024 * 1024, // 50MB
};

/**
 * Buffer Analysis Engine
 *
 * Provides isolated buffer analysis capabilities that can be selectively
 * enabled or disabled to manage false positives and performance.
 */
export class BufferAnalysisEngine {
  private readonly config: Required<BufferAnalysisConfig>;
  private readonly logger = new Logger(BufferAnalysisEngine.name);
  private enabled = true;

  constructor(config?: BufferAnalysisConfig) {
    this.config = { ...DEFAULT_BUFFER_ANALYSIS_CONFIG, ...config };

    // Check environment variable to override default enabled state
    const envDisabled = process.env.DISABLE_BUFFER_ANALYSIS === 'true';
    if (envDisabled) {
      this.enabled = false;
      this.logger.warn(
        'Buffer analysis disabled by environment variable DISABLE_BUFFER_ANALYSIS',
      );
    }
  }

  /**
   * Enable the buffer analysis engine
   */
  enable(): void {
    this.enabled = true;
  }

  /**
   * Disable the buffer analysis engine
   */
  disable(): void {
    this.enabled = false;
  }

  /**
   * Check if the engine is enabled
   */
  isEnabled(): boolean {
    return this.enabled;
  }

  /**
   * Analyze buffer content for MIME type and suspicious patterns
   */
  analyzeBuffer(buffer: Buffer, filename?: string): BufferAnalysisResult {
    // Check if analysis is disabled
    if (!this.enabled) {
      return {
        detectedMimeType: null,
        hasSuspiciousPatterns: false,
        suspiciousPatterns: [],
        confidence: 0,
        analysisSkipped: true,
        skipReason: 'Buffer analysis engine is disabled',
      };
    }

    // Check file size limits
    if (this.config.skipLargeFiles && buffer.length > this.config.maxFileSize) {
      return {
        detectedMimeType: null,
        hasSuspiciousPatterns: false,
        suspiciousPatterns: [],
        confidence: 0,
        analysisSkipped: true,
        skipReason: `File too large (${buffer.length} bytes > ${this.config.maxFileSize} bytes)`,
      };
    }

    const result: BufferAnalysisResult = {
      detectedMimeType: null,
      hasSuspiciousPatterns: false,
      suspiciousPatterns: [],
      confidence: 100,
      analysisSkipped: false,
    };

    try {
      // Detect MIME type from magic bytes
      if (this.config.enableMagicBytesDetection) {
        result.detectedMimeType = this.detectMimeTypeFromBuffer(buffer);
      }

      // Analyze suspicious patterns
      if (this.config.enableSuspiciousPatternAnalysis) {
        const { hasSuspicious, patterns } =
          this.analyzeSuspiciousPatterns(buffer);
        result.hasSuspiciousPatterns = hasSuspicious;
        result.suspiciousPatterns = patterns;
      }

      // Calculate confidence based on analysis results
      result.confidence = this.calculateConfidence(buffer, result);

      this.logger.debug(
        `Buffer analysis completed for ${filename || 'unknown'}: ${JSON.stringify(result)}`,
      );

      return result;
    } catch (error) {
      this.logger.error(
        `Buffer analysis failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
      );
      return {
        detectedMimeType: null,
        hasSuspiciousPatterns: false,
        suspiciousPatterns: [],
        confidence: 0,
        analysisSkipped: true,
        skipReason: 'Analysis failed due to error',
      };
    }
  }

  /**
   * Detect MIME type from buffer using magic bytes
   */
  private detectMimeTypeFromBuffer(buffer: Buffer): string | null {
    for (const [mimeType, signatures] of Object.entries(
      MAGIC_BYTES_SIGNATURES,
    )) {
      for (const signature of signatures) {
        if (this.matchesMagicBytes(buffer, signature)) {
          return mimeType;
        }
      }
    }
    return null;
  }

  /**
   * Check if buffer matches a magic bytes signature
   */
  private matchesMagicBytes(
    buffer: Buffer,
    signature: (number | null)[],
  ): boolean {
    if (buffer.length < signature.length) {
      return false;
    }

    for (let i = 0; i < signature.length; i++) {
      // eslint-disable-next-line security/detect-object-injection
      const signatureByte = signature[i];
      // eslint-disable-next-line security/detect-object-injection
      if (signatureByte !== null && buffer[i] !== signatureByte) {
        return false;
      }
    }

    return true;
  }

  /**
   * Analyze buffer for suspicious patterns
   */
  private analyzeSuspiciousPatterns(buffer: Buffer): {
    hasSuspicious: boolean;
    patterns: string[];
  } {
    const analysisDepth = Math.min(buffer.length, this.config.maxAnalysisDepth);
    const analysisBuffer = buffer.subarray(0, analysisDepth);

    const suspiciousPatterns = [
      // JavaScript in unexpected places
      { pattern: Buffer.from('<script', 'utf8'), name: 'HTML Script Tag' },
      {
        pattern: Buffer.from('javascript:', 'utf8'),
        name: 'JavaScript Protocol',
      },
      { pattern: Buffer.from('vbscript:', 'utf8'), name: 'VBScript Protocol' },
      { pattern: Buffer.from('/JavaScript', 'utf8'), name: 'PDF JavaScript' },
      { pattern: Buffer.from('alert(', 'utf8'), name: 'JavaScript Alert' },

      // Common exploit patterns
      { pattern: Buffer.from('eval(', 'utf8'), name: 'JavaScript Eval' },
      { pattern: Buffer.from('exec(', 'utf8'), name: 'Execution Command' },
      { pattern: Buffer.from('system(', 'utf8'), name: 'System Command' },

      // Shell commands
      { pattern: Buffer.from('#!/bin/', 'utf8'), name: 'Shell Shebang' },
      { pattern: Buffer.from('cmd.exe', 'utf8'), name: 'Windows Command' },

      // SQL injection patterns
      { pattern: Buffer.from('DROP TABLE', 'utf8'), name: 'SQL Drop Command' },
      { pattern: Buffer.from('UNION SELECT', 'utf8'), name: 'SQL Union' },
    ];

    const foundPatterns: string[] = [];

    for (const { pattern, name } of suspiciousPatterns) {
      if (analysisBuffer.includes(pattern)) {
        foundPatterns.push(name);
      }
    }

    return {
      hasSuspicious: foundPatterns.length > 0,
      patterns: foundPatterns,
    };
  }

  /**
   * Calculate confidence score for analysis results
   */
  private calculateConfidence(
    buffer: Buffer,
    result: BufferAnalysisResult,
  ): number {
    let confidence = 100;

    // Reduce confidence if MIME type couldn't be detected
    if (!result.detectedMimeType) {
      confidence -= 20;
    }

    // Reduce confidence if suspicious patterns found
    if (result.hasSuspiciousPatterns) {
      confidence -= result.suspiciousPatterns.length * 10;
    }

    // Reduce confidence for very small files (harder to analyze)
    if (buffer.length < 100) {
      confidence -= 15;
    }

    return Math.max(0, Math.min(100, confidence));
  }

  /**
   * Get current configuration
   */
  getConfig(): Required<BufferAnalysisConfig> {
    return { ...this.config };
  }

  /**
   * Update configuration
   */
  updateConfig(newConfig: Partial<BufferAnalysisConfig>): void {
    Object.assign(this.config, newConfig);
    this.logger.log('Buffer analysis configuration updated');
  }
}

/**
 * Singleton instance for global use
 */
let globalBufferAnalysisEngine: BufferAnalysisEngine | null = null;

/**
 * Get or create global buffer analysis engine instance
 */
export function getBufferAnalysisEngine(
  config?: BufferAnalysisConfig,
): BufferAnalysisEngine {
  if (!globalBufferAnalysisEngine) {
    globalBufferAnalysisEngine = new BufferAnalysisEngine(config);
    // Ensure it starts enabled by default
    globalBufferAnalysisEngine.enable();
  }
  return globalBufferAnalysisEngine;
}

/**
 * Utility function to analyze buffer with global engine
 */
export function analyzeBuffer(
  buffer: Buffer,
  filename?: string,
  config?: BufferAnalysisConfig,
): BufferAnalysisResult {
  const engine = getBufferAnalysisEngine(config);
  return engine.analyzeBuffer(buffer, filename);
}

/**
 * Utility function to enable/disable buffer analysis globally
 */
export function setBufferAnalysisEnabled(enabled: boolean): void {
  const engine = getBufferAnalysisEngine();
  if (enabled) {
    engine.enable();
  } else {
    engine.disable();
  }
}

/**
 * Check if buffer analysis is enabled globally
 */
export function isBufferAnalysisEnabled(): boolean {
  const engine = getBufferAnalysisEngine();
  return engine.isEnabled();
}

/**
 * Debug utility to log buffer analysis engine status
 * Only logs in development or when explicitly enabled
 */
export function logBufferAnalysisStatus(force = false): void {
  // Only log in development environment or when forced
  if (!force && process.env.NODE_ENV === 'production') {
    return;
  }

  const engine = getBufferAnalysisEngine();
  const logger = new Logger('BufferAnalysisDebug');

  logger.debug(`Buffer Analysis Engine Status:`);
  logger.debug(`- Enabled: ${engine.isEnabled()}`);
  logger.debug(
    `- Environment DISABLE_BUFFER_ANALYSIS: ${process.env.DISABLE_BUFFER_ANALYSIS || 'not set'}`,
  );
  logger.debug(
    `- Global instance exists: ${globalBufferAnalysisEngine !== null}`,
  );
}
