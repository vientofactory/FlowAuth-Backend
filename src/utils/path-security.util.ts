import { resolve, normalize, relative } from 'path';

/**
 * Safely resolve a user-provided path within a base directory
 * Prevents path traversal attacks
 */
export function safePath(userPath: string, baseDir: string): string {
  // Normalize the user input to handle '..' and other path tricks
  const normalizedPath = normalize(userPath);

  // Resolve the full path
  const resolvedPath = resolve(baseDir, normalizedPath);
  const resolvedBaseDir = resolve(baseDir);

  // Check if the resolved path is within the base directory
  const relativePath = relative(resolvedBaseDir, resolvedPath);

  // If the relative path starts with '..' or is an absolute path, it's trying to escape
  if (relativePath.startsWith('..') || resolve(relativePath) === relativePath) {
    throw new Error('Invalid path: Directory traversal detected');
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
  return filename
    .replace(/[\\/:*?"<>|]/g, '_') // Replace filesystem-reserved characters
    .replace(/\.\./g, '_') // Replace path traversal attempts
    .replace(/\0/g, '') // Remove null bytes
    .trim() // Remove leading/trailing whitespace
    .substring(0, 255); // Limit length
}
