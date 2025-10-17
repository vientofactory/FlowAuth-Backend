import { resolve, normalize, relative, isAbsolute, sep } from 'path';

/**
 * Safely resolve a user-provided path within a base directory
 * Prevents path traversal attacks with comprehensive validation
 */
export function safePath(userPath: string, baseDir: string): string {
  // Input validation
  if (!userPath || typeof userPath !== 'string') {
    throw new Error('Invalid path: Path must be a non-empty string');
  }

  if (!baseDir || typeof baseDir !== 'string') {
    throw new Error('Invalid base directory: Must be a non-empty string');
  }

  // Prevent null bytes and control characters
  const hasNullByte = userPath.includes('\0');
  const hasControlChars = userPath.split('').some((char) => {
    const code = char.charCodeAt(0);
    return (code >= 1 && code <= 31) || (code >= 127 && code <= 159);
  });

  if (hasNullByte || hasControlChars) {
    throw new Error('Invalid path: Contains null bytes or control characters');
  }

  // Prevent absolute paths in user input
  if (isAbsolute(userPath)) {
    throw new Error('Invalid path: Absolute paths are not allowed');
  }

  // Sanitize and normalize the user input
  let sanitizedPath = userPath
    .replace(/[<>:"|?*]/g, '') // Remove dangerous characters
    .trim();

  // Check for directory traversal patterns before normalization
  if (sanitizedPath.includes('..') || sanitizedPath.includes('.\\')) {
    throw new Error('Invalid path: Directory traversal pattern detected');
  }

  sanitizedPath = sanitizedPath.replace(/\.{2,}/g, '.'); // Replace multiple dots

  if (!sanitizedPath) {
    throw new Error('Invalid path: Path becomes empty after sanitization');
  }

  const normalizedPath = normalize(sanitizedPath);

  // Additional check for path traversal patterns after normalization
  if (
    normalizedPath.includes('..') ||
    normalizedPath.includes(sep + '..' + sep) ||
    normalizedPath.startsWith('..' + sep) ||
    normalizedPath.endsWith(sep + '..')
  ) {
    throw new Error(
      'Invalid path: Directory traversal detected in normalized path',
    );
  }

  // Safely resolve paths without using user input directly in resolve()
  // nosemgrep: javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal
  const resolvedBaseDir = resolve(baseDir);
  // nosemgrep: javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal
  const resolvedPath = resolve(resolvedBaseDir, normalizedPath);

  // Verify the resolved path is within the base directory
  const relativePath = relative(resolvedBaseDir, resolvedPath);

  // Enhanced validation: check for any escape attempts
  if (
    relativePath.startsWith('..') ||
    isAbsolute(relativePath) ||
    relativePath.includes(sep + '..' + sep) ||
    relativePath === '..'
  ) {
    throw new Error('Invalid path: Resolved path escapes base directory');
  }

  return resolvedPath;
}

/**
 * Validate filename to prevent malicious names
 */
export function validateFilename(filename: string): boolean {
  // Check for null bytes and other dangerous characters
  if (filename.includes('\0') || filename.includes('..')) {
    return false;
  }

  // Check for reserved names (Windows)
  const reserved = /^(con|prn|aux|nul|com[0-9]|lpt[0-9])(\.|$)/i;
  if (reserved.test(filename)) {
    return false;
  }

  // Check for control characters and other dangerous patterns
  for (let i = 0; i < filename.length; i++) {
    const charCode = filename.charCodeAt(i);
    if (
      (charCode >= 0 && charCode <= 31) ||
      (charCode >= 128 && charCode <= 159)
    ) {
      return false;
    }
  }

  return true;
}

/**
 * Sanitize filename by removing or replacing dangerous characters
 */
export function sanitizeFilename(filename: string): string {
  // Remove or replace dangerous characters
  let sanitized = filename
    .replace(/[\\/:*?"<>|]/g, '_') // Replace filesystem-reserved characters
    .replace(/\0/g, '') // Remove null bytes
    .trim() // Remove leading/trailing whitespace
    .substring(0, 255); // Limit length

  // Replace path traversal attempts - keep one dot for extensions
  sanitized = sanitized.replace(/\.\.+/g, '_');

  // Replace control characters manually
  sanitized = sanitized
    .split('')
    .map((char) => {
      const code = char.charCodeAt(0);
      if ((code >= 1 && code <= 31) || (code >= 127 && code <= 159)) {
        return '_';
      }
      return char;
    })
    .join('');

  return sanitized;
}

/**
 * Advanced path validation for user inputs
 * Prevents various attack vectors including Unicode normalization attacks
 */
export function validatePathInput(input: string): boolean {
  if (!input || typeof input !== 'string') {
    return false;
  }

  // Check for dangerous patterns
  const dangerousPatterns = [
    /\.\./, // Directory traversal
    /\0/, // Null bytes
    /[<>:"|?*]/, // Windows reserved characters
    /^[./]/, // Starts with dot or slash
    /[./]$/, // Ends with dot or slash
    /\/{2,}/, // Multiple consecutive slashes
    /\\{2,}/, // Multiple consecutive backslashes (Windows)
  ];

  return !dangerousPatterns.some((pattern) => pattern.test(input));
}

/**
 * Create a secure subdirectory path within a base directory
 * Useful for organizing uploads by user, date, etc.
 */
export function createSecureSubdirectory(
  subdirectory: string,
  baseDir: string,
): string {
  if (!validatePathInput(subdirectory)) {
    throw new Error('Invalid subdirectory name');
  }

  const sanitizedSubdir = sanitizeFilename(subdirectory);
  return safePath(sanitizedSubdir, baseDir);
}
