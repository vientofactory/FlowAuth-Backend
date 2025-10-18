/**
 * URL validation utility
 * Addressing validator.js CVE-2025-56200 vulnerability
 *
 * validator.js isURL() function uses '://' as protocol delimiter,
 * but browsers use ':' as delimiter, allowing bypass attacks due to parsing differences.
 */

/**
 * Check if hostname is an IP address (IPv4 or IPv6)
 */
function isIPAddress(hostname: string): boolean {
  // Perform simple validation without using Node.js built-in modules

  // Check IPv4 basic pattern
  if (hostname.includes('.') && !hostname.includes(':')) {
    const parts = hostname.split('.');
    if (parts.length === 4) {
      return parts.every((part) => {
        const num = parseInt(part, 10);
        return !isNaN(num) && num >= 0 && num <= 255 && part === num.toString();
      });
    }
  }

  // Check IPv6 basic pattern (remove brackets)
  const cleanHostname = hostname.replace(/^\[|\]$/g, '');
  if (cleanHostname.includes(':')) {
    // Check basic IPv6 format
    const parts = cleanHostname.split(':');
    return parts.length >= 2 && parts.length <= 8;
  }

  return false;
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
      if (
        input.includes('@') &&
        input.indexOf('@') < input.indexOf(url.hostname)
      ) {
        return false;
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
  const ipv4Regex = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
  const ipv4Match = cleanHostname.match(ipv4Regex);

  if (ipv4Match) {
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
  }

  // Check IPv6 private ranges (simple check)
  if (cleanHostname.includes(':')) {
    const lowerHostname = cleanHostname.toLowerCase();
    // Link-local (fe80::/10)
    if (
      lowerHostname.startsWith('fe8') ||
      lowerHostname.startsWith('fe9') ||
      lowerHostname.startsWith('fea') ||
      lowerHostname.startsWith('feb')
    ) {
      return true;
    }
    // Unique local (fc00::/7)
    if (lowerHostname.startsWith('fc') || lowerHostname.startsWith('fd')) {
      return true;
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
