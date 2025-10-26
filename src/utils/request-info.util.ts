import { Request } from 'express';

/**
 * Utility class for extracting client information from HTTP requests
 */
export class RequestInfoUtils {
  /**
   * Extract User-Agent information from request
   * @param request HTTP request object
   * @returns User-Agent string or 'unknown'
   */
  static getUserAgent(request: Request): string {
    const userAgent =
      request.get('User-Agent') ?? request.headers['user-agent'];
    return typeof userAgent === 'string' ? userAgent : 'unknown';
  }

  /**
   * Extract client IP address from request
   * Prioritizes X-Forwarded-For header, then X-Real-IP, then direct connection IP
   * @param request HTTP request object
   * @returns IP address string or 'unknown'
   */
  static getClientIp(request: Request): string {
    // Check X-Forwarded-For header (for proxy/load balancer environments)
    const xForwardedFor = request.get('X-Forwarded-For');
    if (xForwardedFor) {
      // X-Forwarded-For may contain comma-separated IP list (first one is actual client)
      const ips = xForwardedFor.split(',').map((ip) => ip.trim());
      const clientIp = ips[0];
      if (clientIp && clientIp !== 'unknown') {
        return clientIp;
      }
    }

    // Check X-Real-IP header (used by nginx, etc.)
    const xRealIp = request.get('X-Real-IP');
    if (xRealIp && xRealIp !== 'unknown') {
      return xRealIp;
    }

    // Use direct connection IP address
    const directIp = request.ip ?? (request as any).connection?.remoteAddress;
    if (directIp && typeof directIp === 'string' && directIp !== 'unknown') {
      return directIp;
    }

    return 'unknown';
  }

  /**
   * Extract client information from request in one call
   * @param request HTTP request object
   * @returns Client information object
   */
  static getClientInfo(request: Request): {
    userAgent: string;
    ipAddress: string;
  } {
    return {
      userAgent: this.getUserAgent(request),
      ipAddress: this.getClientIp(request),
    };
  }
}
