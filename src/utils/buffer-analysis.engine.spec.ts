/**
 * Buffer Analysis Engine Edge Cases Test Suite
 *
 * Comprehensive tests for edge cases and attack vectors
 * that the buffer analysis engine should handle.
 */

import {
  BufferAnalysisEngine,
  BufferAnalysisResult,
  getBufferAnalysisEngine,
} from './buffer-analysis.engine';

describe('Buffer Analysis Engine - Edge Cases', () => {
  let engine: BufferAnalysisEngine;

  beforeEach(() => {
    engine = new BufferAnalysisEngine();
    engine.enable();
  });

  afterEach(() => {
    engine.enable(); // Reset for next test
  });

  describe('Corrupted and Truncated Files', () => {
    it('should handle truncated magic bytes gracefully', () => {
      const truncatedJpeg = Buffer.from([0xff]); // Only first byte of JPEG
      const result = engine.analyzeBuffer(truncatedJpeg, 'truncated.jpg');

      expect(result.detectedMimeType).toBeNull();
      expect(result.confidence).toBeLessThan(100);
      expect(result.analysisSkipped).toBe(false);
    });

    it('should handle completely corrupted magic bytes', () => {
      const corruptedPng = Buffer.from([
        0x00, 0x00, 0x00, 0x00, 0x0d, 0x0a, 0x1a, 0x0a,
      ]);
      const result = engine.analyzeBuffer(corruptedPng, 'corrupted.png');

      expect(result.detectedMimeType).toBeNull();
      expect(result.confidence).toBeLessThan(100);
    });

    it('should handle empty buffers', () => {
      const emptyBuffer = Buffer.alloc(0);
      const result = engine.analyzeBuffer(emptyBuffer, 'empty.jpg');

      expect(result.detectedMimeType).toBeNull();
      expect(result.confidence).toBeLessThan(100); // Low confidence for empty buffers
    });

    it('should handle single-byte buffers', () => {
      const singleByte = Buffer.from([0xff]);
      const result = engine.analyzeBuffer(singleByte, 'single.dat');

      expect(result.detectedMimeType).toBeNull();
      expect(result.confidence).toBeLessThan(100);
    });

    it('should handle files with only magic bytes (no content)', () => {
      const onlyMagicJpeg = Buffer.from([0xff, 0xd8, 0xff]);
      const result = engine.analyzeBuffer(onlyMagicJpeg, 'tiny.jpg');

      expect(result.detectedMimeType).toBe('image/jpeg');
      expect(result.confidence).toBeLessThan(100); // Low confidence due to small size
    });
  });

  describe('Polyglot and Multi-format Files', () => {
    it('should detect files with multiple format signatures', () => {
      const polyglotBuffer = Buffer.concat([
        Buffer.from([0xff, 0xd8, 0xff, 0xe0]), // JPEG magic
        Buffer.alloc(100, 0x41), // Padding with 'A'
        Buffer.from([0x50, 0x4b, 0x03, 0x04]), // ZIP magic
        Buffer.from('PK_FILE_CONTENT'),
      ]);

      const result = engine.analyzeBuffer(polyglotBuffer, 'polyglot.jpg');

      expect(result.detectedMimeType).toBe('image/jpeg'); // First detected format
      expect(result.analysisSkipped).toBe(false);
    });

    it('should handle files with conflicting format indicators', () => {
      const conflictingBuffer = Buffer.concat([
        Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), // PNG magic
        Buffer.from([0xff, 0xd8, 0xff, 0xe0]), // JPEG magic later
        Buffer.from('MIXED_CONTENT'),
      ]);

      const result = engine.analyzeBuffer(conflictingBuffer, 'conflicting.png');

      expect(result.detectedMimeType).toBe('image/png'); // First match wins
    });

    it('should detect multiple suspicious patterns in single file', () => {
      const multiThreatBuffer = Buffer.concat([
        Buffer.from([0xff, 0xd8, 0xff, 0xe0]), // JPEG magic
        Buffer.from('<script>alert("xss")</script>'), // HTML Script
        Buffer.from('eval("malicious")'), // JavaScript Eval
        Buffer.from('DROP TABLE users'), // SQL injection
        Buffer.from('system("rm -rf /")'), // System command
        Buffer.from('#!/bin/bash'), // Shell shebang
      ]);

      const result = engine.analyzeBuffer(multiThreatBuffer, 'multithreat.jpg');

      expect(result.hasSuspiciousPatterns).toBe(true);
      expect(result.suspiciousPatterns.length).toBeGreaterThanOrEqual(4);
      expect(result.confidence).toBeLessThan(50);
    });
  });

  describe('Large File Handling', () => {
    it('should respect analysis depth limits', () => {
      const engineWithSmallDepth = new BufferAnalysisEngine({
        maxAnalysisDepth: 100,
        enableSuspiciousPatternAnalysis: true,
      });

      const largeBuffer = Buffer.concat([
        Buffer.from([0xff, 0xd8, 0xff, 0xe0]),
        Buffer.alloc(50, 0x41), // Safe content within limit
        Buffer.alloc(200, 0x42), // Content beyond analysis depth
        Buffer.from('<script>alert("hidden")</script>'), // Suspicious content beyond depth
      ]);

      const result = engineWithSmallDepth.analyzeBuffer(
        largeBuffer,
        'large.jpg',
      );

      expect(result.detectedMimeType).toBe('image/jpeg');
      expect(result.hasSuspiciousPatterns).toBe(false); // Pattern is beyond analysis depth
    });

    it('should skip analysis for files exceeding size limit', () => {
      const engineWithSmallLimit = new BufferAnalysisEngine({
        maxFileSize: 1000,
        skipLargeFiles: true,
      });

      const hugeBuffer = Buffer.concat([
        Buffer.from([0xff, 0xd8, 0xff, 0xe0]),
        Buffer.alloc(2000, 0x41), // Exceeds size limit
      ]);

      const result = engineWithSmallLimit.analyzeBuffer(hugeBuffer, 'huge.jpg');

      expect(result.analysisSkipped).toBe(true);
      expect(result.skipReason).toContain('File too large');
      expect(result.detectedMimeType).toBeNull();
    });

    it('should handle maximum size files efficiently', () => {
      const maxSizeBuffer = Buffer.concat([
        Buffer.from([0xff, 0xd8, 0xff, 0xe0]),
        Buffer.alloc(50 * 1024 * 1024 - 4, 0x41), // Almost max size
      ]);

      const startTime = Date.now();
      const result = engine.analyzeBuffer(maxSizeBuffer, 'maxsize.jpg');
      const endTime = Date.now();

      expect(endTime - startTime).toBeLessThan(10000); // Should complete within 10 seconds
      expect(result.detectedMimeType).toBe('image/jpeg');
    });
  });

  describe('Unicode and Encoding Edge Cases', () => {
    it('should handle Unicode in suspicious patterns', () => {
      const unicodeBuffer = Buffer.concat([
        Buffer.from([0xff, 0xd8, 0xff, 0xe0]),
        Buffer.from('<script>alert("𝕌𝕟𝕚𝕔𝕠𝕕𝕖 𝔸𝕝𝕖𝔯𝕥")</script>', 'utf8'),
        Buffer.from('eval("\\u0065\\u0076\\u0061\\u006c")'), // Unicode escape sequences
      ]);

      const result = engine.analyzeBuffer(unicodeBuffer, 'unicode.jpg');

      expect(result.hasSuspiciousPatterns).toBe(true);
      expect(result.suspiciousPatterns).toContain('HTML Script Tag');
      expect(result.suspiciousPatterns).toContain('JavaScript Eval');
    });

    it('should handle null bytes and control characters', () => {
      const nullByteBuffer = Buffer.concat([
        Buffer.from([0xff, 0xd8, 0xff, 0xe0]),
        Buffer.from([0x00, 0x00, 0x00]), // Null bytes
        Buffer.from('<script\0type="text/javascript">'), // Null byte in script tag
        Buffer.from([0x01, 0x02, 0x03, 0x1f]), // Control characters
        Buffer.from('alert("test")</script>'),
      ]);

      const result = engine.analyzeBuffer(nullByteBuffer, 'nullbytes.jpg');

      expect(result.hasSuspiciousPatterns).toBe(true);
      expect(result.suspiciousPatterns).toContain('HTML Script Tag');
    });

    it('should handle different text encodings', () => {
      const utf16Buffer = Buffer.concat([
        Buffer.from([0xff, 0xd8, 0xff, 0xe0]),
        Buffer.from('<script>alert("test")</script>', 'utf16le'),
      ]);

      const result = engine.analyzeBuffer(utf16Buffer, 'utf16.jpg');

      // Should still detect some patterns even with different encoding
      expect(result.analysisSkipped).toBe(false);
    });
  });

  describe('Memory and Performance Edge Cases', () => {
    it('should handle repetitive patterns without performance degradation', () => {
      const repetitiveBuffer = Buffer.concat([
        Buffer.from([0xff, 0xd8, 0xff, 0xe0]),
        Buffer.from('<script>'.repeat(1000)),
        Buffer.from('alert("test")'.repeat(500)),
        Buffer.from('</script>'.repeat(1000)),
      ]);

      const startTime = Date.now();
      const result = engine.analyzeBuffer(repetitiveBuffer, 'repetitive.jpg');
      const endTime = Date.now();

      expect(endTime - startTime).toBeLessThan(5000); // Should complete within 5 seconds
      expect(result.hasSuspiciousPatterns).toBe(true);
      expect(result.suspiciousPatterns).toContain('HTML Script Tag');
    });

    it('should handle deeply nested pattern structures', () => {
      const nestedBuffer = Buffer.concat([
        Buffer.from([0xff, 0xd8, 0xff, 0xe0]),
        Buffer.from('<script>'.repeat(50)),
        Buffer.from('eval('),
        Buffer.from('system('),
        Buffer.from('"rm -rf /"'),
        Buffer.from(')'),
        Buffer.from(')'),
        Buffer.from('</script>'.repeat(50)),
      ]);

      const result = engine.analyzeBuffer(nestedBuffer, 'nested.jpg');

      expect(result.hasSuspiciousPatterns).toBe(true);
      expect(result.suspiciousPatterns.length).toBeGreaterThanOrEqual(3);
    });

    it('should handle concurrent analysis requests', () => {
      const results: BufferAnalysisResult[] = [];

      for (let i = 0; i < 20; i++) {
        const testBuffer = Buffer.concat([
          Buffer.from([0xff, 0xd8, 0xff, 0xe0]),
          Buffer.from(`<script>alert("test${i}")</script>`),
        ]);

        const result = engine.analyzeBuffer(testBuffer, `concurrent${i}.jpg`);
        results.push(result);
      }

      expect(results.length).toBe(20);

      results.forEach((result) => {
        expect(result.detectedMimeType).toBe('image/jpeg');
        expect(result.hasSuspiciousPatterns).toBe(true);
      });
    });
  });

  describe('Configuration and State Management', () => {
    it('should handle engine disable/enable cycles correctly', () => {
      const testBuffer = Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0x41, 0x42]);

      // First analysis - enabled
      engine.enable();
      const enabledResult = engine.analyzeBuffer(testBuffer, 'test.jpg');

      // Disable and analyze
      engine.disable();
      const disabledResult = engine.analyzeBuffer(testBuffer, 'test.jpg');

      // Re-enable and analyze
      engine.enable();
      const reEnabledResult = engine.analyzeBuffer(testBuffer, 'test.jpg');

      expect(enabledResult.analysisSkipped).toBe(false);
      expect(disabledResult.analysisSkipped).toBe(true);
      expect(reEnabledResult.analysisSkipped).toBe(false);

      expect(enabledResult.detectedMimeType).toBe('image/jpeg');
      expect(disabledResult.detectedMimeType).toBeNull();
      expect(reEnabledResult.detectedMimeType).toBe('image/jpeg');
    });

    it('should respect environment variable overrides', () => {
      // Save original value
      const originalValue = process.env.DISABLE_BUFFER_ANALYSIS;

      try {
        // Test with environment variable set
        process.env.DISABLE_BUFFER_ANALYSIS = 'true';
        const envDisabledEngine = new BufferAnalysisEngine();

        const testBuffer = Buffer.from([0xff, 0xd8, 0xff, 0xe0]);
        const result = envDisabledEngine.analyzeBuffer(testBuffer, 'test.jpg');

        expect(result.analysisSkipped).toBe(true);
        expect(result.skipReason).toContain('disabled');
      } finally {
        // Restore original value
        if (originalValue !== undefined) {
          process.env.DISABLE_BUFFER_ANALYSIS = originalValue;
        } else {
          delete process.env.DISABLE_BUFFER_ANALYSIS;
        }
      }
    });

    it('should handle configuration updates correctly', () => {
      const testBuffer = Buffer.concat([
        Buffer.from([0xff, 0xd8, 0xff, 0xe0]),
        Buffer.from('<script>alert("test")</script>'),
      ]);

      // Initial analysis with pattern detection enabled
      const initialResult = engine.analyzeBuffer(testBuffer, 'test.jpg');

      // Update config to disable pattern analysis
      engine.updateConfig({ enableSuspiciousPatternAnalysis: false });
      const updatedResult = engine.analyzeBuffer(testBuffer, 'test.jpg');

      expect(initialResult.hasSuspiciousPatterns).toBe(true);
      expect(updatedResult.hasSuspiciousPatterns).toBe(false);
    });
  });

  describe('Error Handling and Robustness', () => {
    it('should handle malformed buffer data gracefully', () => {
      // Create a buffer with mixed content that might cause parsing issues
      const malformedBuffer = Buffer.from([
        0xff,
        0xd8,
        0xff,
        0xe0, // JPEG magic
        0x00,
        0x10,
        0x4a,
        0x46,
        0x49,
        0x46,
        0x00,
        0x01, // JFIF header
        0xff,
        0xff,
        0xff,
        0xff, // Invalid marker
        0x3c,
        0x73,
        0x63,
        0x72,
        0x69,
        0x70,
        0x74,
        0x3e, // <script>
      ]);

      expect(() => {
        const result = engine.analyzeBuffer(malformedBuffer, 'malformed.jpg');
        expect(result).toBeDefined();
      }).not.toThrow();
    });

    it('should handle extremely large pattern counts', () => {
      const manyPatternsBuffer = Buffer.concat([
        Buffer.from([0xff, 0xd8, 0xff, 0xe0]),
        ...Array(100)
          .fill(0)
          .map(() => Buffer.from('<script>')),
        ...Array(100)
          .fill(0)
          .map(() => Buffer.from('eval(')),
        ...Array(100)
          .fill(0)
          .map(() => Buffer.from('system(')),
      ]);

      const result = engine.analyzeBuffer(
        manyPatternsBuffer,
        'manypatterns.jpg',
      );

      expect(result.hasSuspiciousPatterns).toBe(true);
      expect(result.suspiciousPatterns.length).toBeGreaterThan(0);
      expect(result.confidence).toBeLessThan(100); // Should be very low due to many patterns
    });

    it('should handle buffer modification during analysis', () => {
      const originalBuffer = Buffer.from([
        0xff,
        0xd8,
        0xff,
        0xe0,
        0x3c,
        0x73,
        0x63,
        0x72,
        0x69,
        0x70,
        0x74,
        0x3e, // <script>
      ]);

      // Create a copy since the engine should work with the buffer as-is
      const bufferCopy = Buffer.from(originalBuffer);

      const result = engine.analyzeBuffer(bufferCopy, 'test.jpg');

      // Modify original buffer after analysis starts (shouldn't affect result)
      originalBuffer.fill(0);

      expect(result.detectedMimeType).toBe('image/jpeg');
      expect(result.hasSuspiciousPatterns).toBe(true);
    });
  });

  describe('Magic Bytes Edge Cases', () => {
    it('should handle all defined magic byte signatures', () => {
      // Test a sample of each MIME type
      const testCases = [
        { magic: [0xff, 0xd8, 0xff], expected: 'image/jpeg' },
        {
          magic: [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a],
          expected: 'image/png',
        },
        { magic: [0x47, 0x49, 0x46, 0x38, 0x37, 0x61], expected: 'image/gif' },
        { magic: [0x25, 0x50, 0x44, 0x46], expected: 'application/pdf' },
        { magic: [0x50, 0x4b, 0x03, 0x04], expected: 'application/zip' },
        { magic: [0x4d, 0x5a], expected: 'application/x-msdownload' },
      ];

      testCases.forEach(({ magic, expected }) => {
        const buffer = Buffer.from(magic);
        const result = engine.analyzeBuffer(buffer, 'test');
        expect(result.detectedMimeType).toBe(expected);
      });
    });

    it('should handle magic bytes with wildcards correctly', () => {
      // Test WEBP format which has wildcards in signature
      const webpBuffer = Buffer.from([
        0x52,
        0x49,
        0x46,
        0x46, // RIFF
        0x12,
        0x34,
        0x56,
        0x78, // Size (wildcard bytes)
        0x57,
        0x45,
        0x42,
        0x50, // WEBP
      ]);

      const result = engine.analyzeBuffer(webpBuffer, 'test.webp');
      expect(result.detectedMimeType).toBe('image/webp');
    });

    it('should handle partial magic byte matches', () => {
      // Create buffer with partial JPEG signature
      const partialJpeg = Buffer.from([0xff, 0xd8]); // Missing third byte
      const result = engine.analyzeBuffer(partialJpeg, 'partial.jpg');

      expect(result.detectedMimeType).toBeNull(); // Should not match partial signature
    });
  });

  describe('Global Engine Instance Management', () => {
    it('should manage global instance correctly', () => {
      const globalEngine1 = getBufferAnalysisEngine();
      const globalEngine2 = getBufferAnalysisEngine();

      expect(globalEngine1).toBe(globalEngine2); // Should be same instance

      globalEngine1.disable();
      expect(globalEngine2.isEnabled()).toBe(false); // Should affect same instance

      globalEngine1.enable();
      expect(globalEngine2.isEnabled()).toBe(true);
    });

    it('should handle global configuration changes', () => {
      const globalEngine = getBufferAnalysisEngine();
      const originalConfig = globalEngine.getConfig();

      globalEngine.updateConfig({
        maxAnalysisDepth: 500,
        enableSuspiciousPatternAnalysis: false,
      });

      const updatedConfig = globalEngine.getConfig();
      expect(updatedConfig.maxAnalysisDepth).toBe(500);
      expect(updatedConfig.enableSuspiciousPatternAnalysis).toBe(false);

      // Restore original config
      globalEngine.updateConfig(originalConfig);
    });
  });
});
