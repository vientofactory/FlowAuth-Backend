/**
 * URL validation utility
 * Addressing validator.js CVE-2025-56200 vulnerability
 *
 * validator.js isURL() function uses '://' as protocol delimiter,
 * but browsers use ':' as delimiter, allowing bypass attacks due to parsing differences.
 *
 * IPv6 Validation Features:
 * - Proper hexadecimal validation for each segment
 * - Support for address compression (::)
 * - IPv4-mapped IPv6 address validation (::ffff:192.0.2.1)
 * - IPv4-compatible IPv6 address validation (deprecated format)
 * - Comprehensive private network detection including:
 *   - Loopback addresses (::1)
 *   - Link-local addresses (fe80::/10)
 *   - Unique local addresses (fc00::/7)
 *   - Site-local addresses (fec0::/10, deprecated)
 *   - IPv4-mapped private addresses
 *
 * Limitations:
 * - Does not validate against reserved IPv6 ranges beyond private networks
 * - Does not perform DNS resolution or reachability checks
 * - Focuses on structural validation and security-relevant ranges
 */

/**
 * Check if hostname is a valid IPv4 address
 */
function isIPv4Address(hostname: string): boolean {
  if (hostname.includes(':')) {
    return false; // IPv4 should not contain colons
  }

  const parts = hostname.split('.');
  if (parts.length !== 4) {
    return false;
  }

  return parts.every((part) => {
    // Check for leading zeros (except "0" itself)
    if (part.length > 1 && part.startsWith('0')) {
      return false;
    }

    const num = parseInt(part, 10);
    return !isNaN(num) && num >= 0 && num <= 255 && part === num.toString();
  });
}

/**
 * Check if hostname is a valid IPv6 address
 * Implements proper IPv6 validation according to RFC 5952
 */
function isIPv6Address(hostname: string): boolean {
  // Remove brackets if present
  const cleanHostname = hostname.replace(/^\[|\]$/g, '');

  // Must contain at least one colon
  if (!cleanHostname.includes(':')) {
    return false;
  }

  // Check for double colon compression
  const doubleColonCount = (cleanHostname.match(/::/g) || []).length;
  if (doubleColonCount > 1) {
    return false; // Only one :: allowed
  }

  // Handle IPv4-mapped IPv6 addresses (e.g., ::ffff:192.0.2.1)
  const ipv4MappedMatch = cleanHostname.match(/^(.+):(\d+\.\d+\.\d+\.\d+)$/);
  if (ipv4MappedMatch) {
    const [, ipv6Part, ipv4Part] = ipv4MappedMatch;
    if (!isIPv4Address(ipv4Part)) {
      return false;
    }
    // Validate the IPv6 part (should end with ::ffff or similar)
    const expandedIPv6Part = ipv6Part + ':0:0';
    return isIPv6AddressPart(expandedIPv6Part);
  }

  return isIPv6AddressPart(cleanHostname);
}

/**
 * Validate IPv6 address parts and structure
 */
function isIPv6AddressPart(address: string): boolean {
  const parts = address.split(':');

  // Handle compression
  if (address.includes('::')) {
    const [before, after] = address.split('::', 2);
    const beforeParts = before ? before.split(':') : [];
    const afterParts = after ? after.split(':') : [];

    // Total parts should not exceed 8 when expanded
    const totalParts = beforeParts.length + afterParts.length;
    if (totalParts >= 8) {
      return false;
    }

    // Validate each part
    return [...beforeParts, ...afterParts].every(isValidHexPart);
  } else {
    // No compression - must have exactly 8 parts
    if (parts.length !== 8) {
      return false;
    }
    return parts.every(isValidHexPart);
  }
}

/**
 * Validate a single hexadecimal part of IPv6 address
 */
function isValidHexPart(part: string): boolean {
  if (!part) {
    return true; // Empty parts are valid in compression context
  }

  // Must be 1-4 hexadecimal characters
  if (part.length === 0 || part.length > 4) {
    return false;
  }

  // Must contain only hexadecimal characters
  return /^[0-9a-fA-F]+$/.test(part);
}

/**
 * Check if hostname is an IP address (IPv4 or IPv6)
 */
function isIPAddress(hostname: string): boolean {
  return isIPv4Address(hostname) || isIPv6Address(hostname);
}

/**
 * Safe URL validation options
 */
export interface SafeUrlOptions {
  // Allowed protocols
  allowedProtocols?: string[];
  // Allow HTTP protocol (default: false, HTTPS only)
  allowHttp?: boolean;
  // Allow localhost and private IPs (default: false)
  allowPrivateNetworks?: boolean;
  // Maximum URL length
  maxLength?: number;
  // Validate hostname format
  validateHostname?: boolean;
}

/**
 * Default safe URL validation options
 */
const DEFAULT_SAFE_URL_OPTIONS: SafeUrlOptions = {
  allowedProtocols: ['https:', 'http:'],
  allowHttp: false,
  allowPrivateNetworks: false,
  maxLength: 2048,
  validateHostname: true,
};

/**
 * Safe URL validation function
 * Alternative function to solve validator.js isURL() vulnerability
 */
export function isSafeUrl(
  input: string,
  options: SafeUrlOptions = {},
): boolean {
  const opts = { ...DEFAULT_SAFE_URL_OPTIONS, ...options };

  // Basic input validation
  if (!input || typeof input !== 'string') {
    return false;
  }

  // Length limit validation
  if (input.length > opts.maxLength!) {
    return false;
  }

  // Whitespace character validation
  if (input.trim() !== input || /\s/.test(input)) {
    return false;
  }

  // Dangerous character validation - safely check control characters
  const hasControlChars = input.split('').some((char) => {
    const code = char.charCodeAt(0);
    return (code >= 0 && code <= 31) || (code >= 127 && code <= 159);
  });

  if (hasControlChars) {
    return false;
  }

  try {
    // CVE-2025-56200 mitigation: Protocol parsing difference validation
    // 1. Browser approach: Parse protocol based on first ':'
    const colonIndex = input.indexOf(':');
    if (colonIndex === -1) {
      return false;
    }

    const protocolFromInput = input.substring(0, colonIndex + 1);

    // 2. Additional protocol structure validation
    // Check if '://' pattern is at the correct position
    if (!input.substring(colonIndex).startsWith('://')) {
      return false;
    }

    // 3. Check allowed protocols
    if (!opts.allowedProtocols!.includes(protocolFromInput)) {
      return false;
    }

    // 4. Additional structure validation with URL object
    const url = new URL(input);

    // 5. Check if URL object protocol matches input parsed protocol
    if (url.protocol !== protocolFromInput) {
      return false;
    }

    // 6. Check if '://' immediately follows scheme (prevent CVE bypass)
    const expectedStart = protocolFromInput + '//';
    if (!input.startsWith(expectedStart)) {
      return false;
    }

    // HTTP/HTTPS protocol special validation
    if (protocolFromInput === 'http:' && !opts.allowHttp) {
      return false;
    }

    // Hostname validation
    if (opts.validateHostname) {
      if (!url.hostname || url.hostname.length === 0) {
        return false;
      }

      // Hostname length limit (RFC 1035)
      if (url.hostname.length > 253) {
        return false;
      }

      // Reject if @ character is present (userinfo present)
      if (input.includes('@')) {
        const hostnameIndex = input.indexOf(url.hostname);
        if (hostnameIndex === -1) {
          // Hostname not found in input - potential security issue
          return false;
        }
        if (input.indexOf('@') < hostnameIndex) {
          return false;
        }
      }

      // Domain name validation for non-IP addresses
      if (!isIPAddress(url.hostname)) {
        // Label length limit (RFC 1035)
        const labels = url.hostname.split('.');
        for (const label of labels) {
          if (label.length === 0 || label.length > 63) {
            return false;
          }
          // Labels allow only letters, numbers, and hyphens
          if (!/^[a-zA-Z0-9-]+$/.test(label)) {
            return false;
          }
          // Cannot start or end with hyphen
          if (label.startsWith('-') || label.endsWith('-')) {
            return false;
          }
        }
      }
    }

    // Private network validation
    if (!opts.allowPrivateNetworks && isPrivateNetwork(url.hostname)) {
      return false;
    }

    // Port number validation (if present)
    if (url.port) {
      const portNum = parseInt(url.port, 10);
      if (isNaN(portNum) || portNum < 1 || portNum > 65535) {
        return false;
      }
    }

    return true;
  } catch {
    // Consider as invalid URL when URL creation fails
    return false;
  }
}

/**
 * Check if an IPv4 address is in private/local ranges
 */
function isPrivateIPv4(hostname: string): boolean {
  const ipv4Regex = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
  const ipv4Match = hostname.match(ipv4Regex);

  if (!ipv4Match) {
    return false;
  }

  const [, a, b, c, d] = ipv4Match.map((num) => parseInt(num, 10));

  // Check valid IPv4 range
  if (a > 255 || b > 255 || c > 255 || d > 255) {
    return true; // Consider invalid IP as private
  }

  // Private IP ranges (RFC 1918)
  // 10.0.0.0/8
  if (a === 10) return true;
  // 172.16.0.0/12
  if (a === 172 && b >= 16 && b <= 31) return true;
  // 192.168.0.0/16
  if (a === 192 && b === 168) return true;

  // Link-local (169.254.0.0/16)
  if (a === 169 && b === 254) return true;

  return false;
}

/**
 * Check private network IP addresses
 */
function isPrivateNetwork(hostname: string): boolean {
  // Check localhost
  if (
    hostname === 'localhost' ||
    hostname === '127.0.0.1' ||
    hostname === '::1' ||
    hostname === '[::1]'
  ) {
    return true;
  }

  // Remove brackets from IPv6 addresses
  const cleanHostname = hostname.replace(/^\[|\]$/g, '');

  // Check IPv4 private ranges
  if (cleanHostname.includes('.') && !cleanHostname.includes(':')) {
    return isPrivateIPv4(cleanHostname);
  }

  // Check IPv6 private ranges (comprehensive check)
  if (cleanHostname.includes(':')) {
    const lowerHostname = cleanHostname.toLowerCase();

    // Remove brackets and normalize
    const normalizedIPv6 = lowerHostname.replace(/^\[|\]$/g, '');

    // Loopback (::1)
    if (normalizedIPv6 === '::1' || normalizedIPv6 === '0:0:0:0:0:0:0:1') {
      return true;
    }

    // Link-local (fe80::/10) - fe80:: to febf::
    if (
      normalizedIPv6.startsWith('fe8') ||
      normalizedIPv6.startsWith('fe9') ||
      normalizedIPv6.startsWith('fea') ||
      normalizedIPv6.startsWith('feb')
    ) {
      return true;
    }

    // Unique local (fc00::/7) - fc00:: to fdff::
    if (normalizedIPv6.startsWith('fc') || normalizedIPv6.startsWith('fd')) {
      return true;
    }

    // Site-local (deprecated but still private) - fec0::/10
    if (
      normalizedIPv6.startsWith('fec') ||
      normalizedIPv6.startsWith('fed') ||
      normalizedIPv6.startsWith('fee') ||
      normalizedIPv6.startsWith('fef')
    ) {
      return true;
    }

    // IPv4-mapped IPv6 addresses with private IPv4
    // Handle both dotted decimal and hex representations
    // Examples: ::ffff:192.168.1.1 or ::ffff:c0a8:101
    const ipv4MappedMatch = normalizedIPv6.match(
      /(?:::|^0*:0*:0*:0*:0*:)ffff:(\d+\.\d+\.\d+\.\d+)$/i,
    );
    if (ipv4MappedMatch) {
      return isPrivateIPv4(ipv4MappedMatch[1]);
    }

    // IPv4-mapped with hex representation (after URL parsing)
    const ipv4MappedHexMatch = normalizedIPv6.match(
      /(?:::|^0*:0*:0*:0*:0*:)ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i,
    );
    if (ipv4MappedHexMatch) {
      const part1 = parseInt(ipv4MappedHexMatch[1], 16);
      const part2 = parseInt(ipv4MappedHexMatch[2], 16);
      const ip = `${Math.floor(part1 / 256)}.${part1 % 256}.${Math.floor(part2 / 256)}.${part2 % 256}`;
      return isPrivateIPv4(ip);
    }

    // IPv4-compatible IPv6 addresses (deprecated)
    const ipv4CompatMatch = normalizedIPv6.match(
      /(?:::|^0*:0*:0*:0*:0*:0*:)(\d+\.\d+\.\d+\.\d+)$/,
    );
    if (ipv4CompatMatch) {
      return isPrivateIPv4(ipv4CompatMatch[1]);
    }
  }

  return false;
}

/**
 * OAuth2 redirect URI validation function
 */
export function validateOAuth2RedirectUri(uri: string): boolean {
  return isSafeUrl(uri, {
    allowedProtocols: ['https:', 'http:'],
    allowHttp: process.env.NODE_ENV === 'development', // Allow HTTP only in development
    allowPrivateNetworks: process.env.NODE_ENV === 'development',
    maxLength: 2048,
    validateHostname: true,
  });
}

/**
 * General web URL validation function (HTTPS only)
 */
export function validateWebUrl(url: string): boolean {
  return isSafeUrl(url, {
    allowedProtocols: ['https:'],
    allowHttp: false,
    allowPrivateNetworks: false,
    maxLength: 2048,
    validateHostname: true,
  });
}

/**
 * class-validator compatible URL validation function
 * Safe alternative to @IsUrl decorator
 */
export function isUrlSafe(value: string): boolean {
  return validateWebUrl(value);
}
