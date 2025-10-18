import { timingSafeEqual, randomBytes } from 'crypto';
import * as bcrypt from 'bcrypt';

/**
 * Perform a timing-safe comparison of two strings
 * This helps prevent timing attacks where an attacker could determine
 * the correct value by measuring response times
 */
export function safeStringCompare(a: string, b: string): boolean {
  // If lengths are different, we still want to do a full comparison
  // to prevent timing attacks
  const maxLength = Math.max(a.length, b.length);

  // Pad shorter string with null bytes to make them equal length
  const paddedA = a.padEnd(maxLength, '\0');
  const paddedB = b.padEnd(maxLength, '\0');

  try {
    return timingSafeEqual(
      Buffer.from(paddedA, 'utf8'),
      Buffer.from(paddedB, 'utf8'),
    );
  } catch {
    // If there's an error (e.g., different lengths after conversion), return false
    return false;
  }
}

/**
 * Perform a timing-safe comparison of two buffers
 */
export function safeBufferCompare(a: Buffer, b: Buffer): boolean {
  if (a.length !== b.length) {
    return false;
  }

  try {
    return timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

/**
 * Generate a secure random string for tokens, secrets, etc.
 */
export function generateSecureToken(length = 32): string {
  return randomBytes(length).toString('hex');
}

/**
 * Hash a password or sensitive string with a secure method
 */
export async function secureHash(
  input: string,
  saltRounds = 12,
): Promise<string> {
  return await bcrypt.hash(input, saltRounds);
}

/**
 * Verify a password against a hash using timing-safe comparison
 */
export async function verifySecureHash(
  input: string,
  hash: string,
): Promise<boolean> {
  return await bcrypt.compare(input, hash);
}

/**
 * Perform timing-safe token comparison for OAuth2 tokens, secrets, etc.
 * This function is optimized for comparing tokens and secrets that may vary in length
 */
export function safeTokenCompare(tokenA: string, tokenB: string): boolean {
  // Normalize tokens to ensure consistent comparison
  const normalizedA = tokenA?.trim() || '';
  const normalizedB = tokenB?.trim() || '';

  // Use safeStringCompare for the actual comparison
  return safeStringCompare(normalizedA, normalizedB);
}

/**
 * Perform timing-safe comparison for client credentials
 * This function handles null/undefined cases safely
 */
export function safeCredentialCompare(
  providedCredential: string | null | undefined,
  storedCredential: string | null | undefined,
): boolean {
  // Handle null/undefined cases with strict equality
  if (providedCredential === null && storedCredential === null) {
    return true; // Both are null
  }

  if (providedCredential === undefined && storedCredential === undefined) {
    return true; // Both are undefined
  }

  if (!providedCredential || !storedCredential) {
    return false; // One is null/undefined, the other isn't, or they are different types
  }

  return safeStringCompare(providedCredential, storedCredential);
}
