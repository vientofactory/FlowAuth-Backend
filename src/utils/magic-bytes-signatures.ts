/**
 * Magic Bytes Signatures for File Type Detection
 *
 * This module contains magic bytes signatures used to identify file types
 * from binary content. These signatures are used by the Buffer Analysis Engine
 * to detect MIME types and prevent file type spoofing.
 *
 * @version 1.0.0
 */

/**
 * Magic bytes signature type definition
 * null values represent wildcard bytes that can be any value
 */
export type MagicBytesSignature = (number | null)[];

/**
 * Magic bytes signature mapping for file type detection
 * Key: MIME type
 * Value: Array of possible magic bytes signatures for that type
 */
export const MAGIC_BYTES_SIGNATURES: Record<string, MagicBytesSignature[]> = {
  // Images
  'image/jpeg': [
    [0xff, 0xd8, 0xff], // JPEG/JFIF
  ],
  'image/png': [
    [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a], // PNG
  ],
  'image/gif': [
    [0x47, 0x49, 0x46, 0x38, 0x37, 0x61], // GIF87a
    [0x47, 0x49, 0x46, 0x38, 0x39, 0x61], // GIF89a
  ],
  'image/webp': [
    [0x52, 0x49, 0x46, 0x46, null, null, null, null, 0x57, 0x45, 0x42, 0x50], // RIFF....WEBP
  ],
  'image/bmp': [
    [0x42, 0x4d], // BM
  ],
  'image/tiff': [
    [0x49, 0x49, 0x2a, 0x00], // II (little endian)
    [0x4d, 0x4d, 0x00, 0x2a], // MM (big endian)
  ],
  'image/svg+xml': [
    [0x3c, 0x73, 0x76, 0x67], // <svg
  ],
  'image/x-icon': [
    [0x00, 0x00, 0x01, 0x00], // ICO
  ],

  // Documents
  'application/pdf': [
    [0x25, 0x50, 0x44, 0x46], // %PDF
  ],
  'application/zip': [
    [0x50, 0x4b, 0x03, 0x04], // PK.. (local file header)
    [0x50, 0x4b, 0x05, 0x06], // PK.. (end of central directory)
    [0x50, 0x4b, 0x07, 0x08], // PK.. (data descriptor)
  ],

  // Microsoft Office (based on ZIP format)
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document': [
    [0x50, 0x4b, 0x03, 0x04], // DOCX (ZIP-based)
  ],
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': [
    [0x50, 0x4b, 0x03, 0x04], // XLSX (ZIP-based)
  ],
  'application/vnd.openxmlformats-officedocument.presentationml.presentation': [
    [0x50, 0x4b, 0x03, 0x04], // PPTX (ZIP-based)
  ],

  // Archives
  'application/x-rar-compressed': [
    [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07], // Rar!..
  ],
  'application/x-7z-compressed': [
    [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c], // 7z
  ],
  'application/gzip': [
    [0x1f, 0x8b], // GZIP
  ],
  'application/x-tar': [
    [0x75, 0x73, 0x74, 0x61, 0x72], // ustar (at offset 257)
  ],

  // Audio
  'audio/mpeg': [
    [0xff, 0xfb], // MP3
    [0x49, 0x44, 0x33], // ID3 tag
  ],
  'audio/wav': [
    [0x52, 0x49, 0x46, 0x46, null, null, null, null, 0x57, 0x41, 0x56, 0x45], // RIFF....WAVE
  ],
  'audio/ogg': [
    [0x4f, 0x67, 0x67, 0x53], // OggS
  ],

  // Video
  'video/mp4': [
    [null, null, null, null, 0x66, 0x74, 0x79, 0x70], // ....ftyp
  ],
  'video/avi': [
    [0x52, 0x49, 0x46, 0x46, null, null, null, null, 0x41, 0x56, 0x49, 0x20], // RIFF....AVI
  ],
  'video/quicktime': [
    [null, null, null, null, 0x6d, 0x6f, 0x6f, 0x76], // ....moov
    [null, null, null, null, 0x6d, 0x64, 0x61, 0x74], // ....mdat
  ],

  // Text and Code
  'text/html': [
    [0x3c, 0x21, 0x44, 0x4f, 0x43, 0x54, 0x59, 0x50, 0x45], // <!DOCTYPE
    [0x3c, 0x68, 0x74, 0x6d, 0x6c], // <html
    [0x3c, 0x48, 0x54, 0x4d, 0x4c], // <HTML
  ],
  'application/xml': [
    [0x3c, 0x3f, 0x78, 0x6d, 0x6c], // <?xml
  ],

  // Executables (potentially dangerous)
  'application/x-msdownload': [
    [0x4d, 0x5a], // MZ (PE executable)
  ],
  'application/x-executable': [
    [0x7f, 0x45, 0x4c, 0x46], // ELF
  ],
  'application/x-mach-binary': [
    [0xfe, 0xed, 0xfa, 0xce], // Mach-O 32-bit
    [0xfe, 0xed, 0xfa, 0xcf], // Mach-O 64-bit
    [0xcf, 0xfa, 0xed, 0xfe], // Mach-O 32-bit (reversed)
    [0xce, 0xfa, 0xed, 0xfe], // Mach-O 64-bit (reversed)
  ],
  'application/java-archive': [
    [0x50, 0x4b, 0x03, 0x04], // JAR (ZIP-based)
  ],
  'application/x-dosexec': [
    [0x4d, 0x5a], // MZ (DOS executable)
  ],

  // Fonts
  'font/woff': [
    [0x77, 0x4f, 0x46, 0x46], // wOFF
  ],
  'font/woff2': [
    [0x77, 0x4f, 0x46, 0x32], // wOF2
  ],
  'font/ttf': [
    [0x00, 0x01, 0x00, 0x00], // TrueType
  ],
  'font/otf': [
    [0x4f, 0x54, 0x54, 0x4f], // OTTO
  ],
};

/**
 * Get all supported MIME types that have magic bytes signatures
 */
export function getSupportedMimeTypes(): string[] {
  return Object.keys(MAGIC_BYTES_SIGNATURES);
}

/**
 * Get magic bytes signatures for a specific MIME type
 */
export function getSignaturesForMimeType(
  mimeType: string,
): MagicBytesSignature[] {
  // eslint-disable-next-line security/detect-object-injection
  return MAGIC_BYTES_SIGNATURES[mimeType] || [];
}

/**
 * Check if a MIME type has magic bytes signatures defined
 */
export function hasMagicBytesSignature(mimeType: string): boolean {
  return mimeType in MAGIC_BYTES_SIGNATURES;
}

/**
 * Security risk levels for file types
 */
export enum SecurityRisk {
  SAFE = 'safe', // Generally safe files (images, audio, video, fonts)
  SUSPICIOUS = 'suspicious', // Potential risk (scripts, archives, etc.)
  DANGEROUS = 'dangerous', // High risk (executable files, binaries, etc.)
  BLOCKED = 'blocked', // Completely blocked files
}

/**
 * File type security classification
 */
export const FILE_SECURITY_CLASSIFICATION: Record<string, SecurityRisk> = {
  // Safe files - Generally safe (images, audio, video, fonts)
  'image/jpeg': SecurityRisk.SAFE,
  'image/png': SecurityRisk.SAFE,
  'image/gif': SecurityRisk.SAFE,
  'image/webp': SecurityRisk.SAFE,
  'image/bmp': SecurityRisk.SAFE,
  'image/tiff': SecurityRisk.SAFE,
  'image/x-icon': SecurityRisk.SAFE,
  'audio/mpeg': SecurityRisk.SAFE,
  'audio/wav': SecurityRisk.SAFE,
  'audio/ogg': SecurityRisk.SAFE,
  'video/mp4': SecurityRisk.SAFE,
  'video/avi': SecurityRisk.SAFE,
  'video/quicktime': SecurityRisk.SAFE,
  'font/woff': SecurityRisk.SAFE,
  'font/woff2': SecurityRisk.SAFE,
  'font/ttf': SecurityRisk.SAFE,
  'font/otf': SecurityRisk.SAFE,

  // Suspicious files - Potential risk (scripts, archives, etc.)
  'application/pdf': SecurityRisk.SUSPICIOUS, // PDF can contain JavaScript
  'image/svg+xml': SecurityRisk.SUSPICIOUS, // SVG can contain scripts
  'text/html': SecurityRisk.SUSPICIOUS, // HTML can contain scripts
  'application/xml': SecurityRisk.SUSPICIOUS, // XML can contain entities
  'application/zip': SecurityRisk.SUSPICIOUS, // Archives can contain executables
  'application/x-rar-compressed': SecurityRisk.SUSPICIOUS,
  'application/x-7z-compressed': SecurityRisk.SUSPICIOUS,
  'application/gzip': SecurityRisk.SUSPICIOUS,
  'application/x-tar': SecurityRisk.SUSPICIOUS,
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document':
    SecurityRisk.SUSPICIOUS,
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet':
    SecurityRisk.SUSPICIOUS,
  'application/vnd.openxmlformats-officedocument.presentationml.presentation':
    SecurityRisk.SUSPICIOUS,

  // Dangerous files - High risk (executable files, binaries, etc.)
  'application/x-msdownload': SecurityRisk.DANGEROUS, // PE executables
  'application/x-executable': SecurityRisk.DANGEROUS, // ELF executables
  'application/x-mach-binary': SecurityRisk.DANGEROUS, // Mach-O executables
  'application/x-dosexec': SecurityRisk.DANGEROUS, // DOS executables
  'application/java-archive': SecurityRisk.DANGEROUS, // JAR files (can be executed)
};

/**
 * Get all dangerous file types (high risk executables)
 */
export function getDangerousFileTypes(): string[] {
  return Object.entries(FILE_SECURITY_CLASSIFICATION)
    .filter(([, risk]) => risk === SecurityRisk.DANGEROUS)
    .map(([mimeType]) => mimeType);
}

/**
 * Get all suspicious file types (potential risk)
 */
export function getSuspiciousFileTypes(): string[] {
  return Object.entries(FILE_SECURITY_CLASSIFICATION)
    .filter(([, risk]) => risk === SecurityRisk.SUSPICIOUS)
    .map(([mimeType]) => mimeType);
}

/**
 * Get all safe file types
 */
export function getSafeFileTypes(): string[] {
  return Object.entries(FILE_SECURITY_CLASSIFICATION)
    .filter(([, risk]) => risk === SecurityRisk.SAFE)
    .map(([mimeType]) => mimeType);
}

/**
 * Get security risk level for a MIME type
 */
export function getSecurityRisk(mimeType: string): SecurityRisk {
  // eslint-disable-next-line security/detect-object-injection
  return FILE_SECURITY_CLASSIFICATION[mimeType] || SecurityRisk.SUSPICIOUS;
}

/**
 * Check if a MIME type is considered dangerous
 */
export function isDangerousMimeType(mimeType: string): boolean {
  return getSecurityRisk(mimeType) === SecurityRisk.DANGEROUS;
}

/**
 * Check if a MIME type is suspicious (potential risk)
 */
export function isSuspiciousMimeType(mimeType: string): boolean {
  return getSecurityRisk(mimeType) === SecurityRisk.SUSPICIOUS;
}

/**
 * Check if a MIME type is safe
 */
export function isSafeMimeType(mimeType: string): boolean {
  return getSecurityRisk(mimeType) === SecurityRisk.SAFE;
}

/**
 * Check if a MIME type should be allowed (not blocked)
 */
export function isAllowedMimeType(mimeType: string): boolean {
  return getSecurityRisk(mimeType) !== SecurityRisk.BLOCKED;
}
