import {
  Injectable,
  PipeTransform,
  ArgumentMetadata,
  BadRequestException,
  Logger,
} from '@nestjs/common';
import { validate, ValidationError } from 'class-validator';
import { plainToClass } from 'class-transformer';

@Injectable()
export class ValidationSanitizationPipe implements PipeTransform<any> {
  private readonly logger = new Logger(ValidationSanitizationPipe.name);

  async transform(value: any, { metatype }: ArgumentMetadata): Promise<any> {
    if (!metatype || !this.toValidate(metatype)) {
      return value;
    }

    // Pre-sanitization security checks (must be done before sanitization to avoid infinite loops)
    this.validateCircularReferences(value, new WeakSet());
    this.validateNestingDepth(value, 0);
    this.validatePayloadSize(value);

    // Comprehensive security sanitization
    value = this.performSecuritySanitization(value);

    // Transform to class instance
    const object = plainToClass(metatype, value) as Record<string, unknown>;

    // Validate the object
    const errors = await validate(object, {
      whitelist: true,
      forbidNonWhitelisted: true,
      forbidUnknownValues: true,
    });

    if (errors.length > 0) {
      throw new BadRequestException({
        message: 'Validation failed',
        errors: this.formatErrors(errors),
      });
    }

    return object;
  }

  private toValidate(metatype: unknown): boolean {
    const types: unknown[] = [String, Boolean, Number, Array, Object];
    return !types.includes(metatype);
  }

  private formatErrors(errors: ValidationError[]): Record<string, unknown> {
    return errors.reduce((acc, error) => {
      if (error.children && error.children.length > 0) {
        acc[error.property] = this.formatErrors(error.children);
      } else {
        acc[error.property] = Object.values(error.constraints || {});
      }
      return acc;
    }, {});
  }

  private performSecuritySanitization(value: unknown): unknown {
    // Handle different input types
    if (value === null || value === undefined) {
      return value;
    }

    if (Array.isArray(value)) {
      return this.sanitizeArray(value);
    }

    if (
      value &&
      typeof value === 'object' &&
      Object.prototype.toString.call(value) === '[object Object]'
    ) {
      return this.sanitizeObject(value as Record<string, unknown>);
    }

    // Handle strings for potential injection attacks
    if (typeof value === 'string') {
      return this.sanitizeString(value);
    }

    // Handle numbers for potential overflow attacks
    if (typeof value === 'number') {
      return this.sanitizeNumber(value);
    }

    return value;
  }

  private sanitizeObject(
    obj: Record<string, unknown>,
  ): Record<string, unknown> {
    // Define dangerous keys that could lead to prototype pollution and other attacks
    const dangerousKeys = [
      '__proto__',
      'constructor',
      'prototype',
      'constructor.prototype',
      '__defineGetter__',
      '__defineSetter__',
      '__lookupGetter__',
      '__lookupSetter__',
      'valueOf',
      'toString',
      'hasOwnProperty',
      'isPrototypeOf',
      'propertyIsEnumerable',
    ];

    const cleanObject: Record<string, unknown> = {};
    let hasViolation = false;

    for (const [key, value] of Object.entries(obj)) {
      // Check if the key itself is dangerous
      if (dangerousKeys.includes(key)) {
        hasViolation = true;
        this.logger.warn(`Blocked dangerous property: ${key}`);
        continue;
      }

      // Check for nested dangerous property paths
      if (this.containsDangerousPath(key)) {
        hasViolation = true;
        this.logger.warn(`Blocked dangerous property path: ${key}`);
        continue;
      }

      // Additional check for constructor.prototype chain attacks
      if (this.isConstructorPrototypeChain(key, value)) {
        hasViolation = true;
        this.logger.warn(`Blocked constructor.prototype chain attack: ${key}`);
        continue;
      }

      // Recursively sanitize nested objects
      if (
        value &&
        typeof value === 'object' &&
        !Array.isArray(value) &&
        value.constructor === Object
      ) {
        cleanObject[key] = this.sanitizeObject(
          value as Record<string, unknown>,
        );
      } else if (Array.isArray(value)) {
        cleanObject[key] = this.sanitizeArray(value);
      } else {
        cleanObject[key] = value;
      }
    }

    if (hasViolation) {
      this.logger.warn('Prototype pollution attempt detected and sanitized:', {
        input: this.getSafeInputDescription(obj),
        sanitized: true,
      });
    }

    return cleanObject;
  }

  private sanitizeArray(arr: unknown[]): unknown[] {
    return arr.map((item) => {
      if (
        item &&
        typeof item === 'object' &&
        !Array.isArray(item) &&
        item.constructor === Object
      ) {
        return this.sanitizeObject(item as Record<string, unknown>);
      } else if (Array.isArray(item)) {
        return this.sanitizeArray(item);
      }
      return item;
    });
  }

  private containsDangerousPath(key: string): boolean {
    // Check for various forms of dangerous property paths
    const dangerousPatterns = [
      /^__proto__$/i,
      /^constructor$/i,
      /^prototype$/i,
      /constructor\.prototype/i,
      /__proto__\./i,
      /\.constructor/i,
      /\.prototype/i,
      /\[constructor\]/i,
      /\[prototype\]/i,
      /\["constructor"\]/i,
      /\["prototype"\]/i,
      /\['constructor'\]/i,
      /\['prototype'\]/i,
      // Additional dangerous patterns
      /__defineGetter__/i,
      /__defineSetter__/i,
      /__lookupGetter__/i,
      /__lookupSetter__/i,
      /\.valueOf/i,
      /\.toString/i,
      // Unicode and encoded variations
      /\\u005f\\u005f/i, // __
      /%5f%5f/i, // URL encoded __
      /\\\\/i, // Escaped backslash attacks
    ];

    return dangerousPatterns.some((pattern) => pattern.test(key));
  }

  private isConstructorPrototypeChain(key: string, value: unknown): boolean {
    // Check if key is 'constructor' and value has 'prototype' property
    if (key === 'constructor' && value && typeof value === 'object') {
      const objValue = value as Record<string, unknown>;
      if ('prototype' in objValue) {
        return true;
      }
    }

    // Check for encoded constructor.prototype patterns
    const constructorPrototypePatterns = [
      /constructor\s*\[\s*['"]*prototype['"]*\s*\]/i,
      /constructor\s*\.\s*prototype/i,
      /\['constructor'\]\s*\[\s*['"]*prototype['"]*\s*\]/i,
      /\["constructor"\]\s*\[\s*['"]*prototype['"]*\s*\]/i,
    ];

    return constructorPrototypePatterns.some((pattern) => pattern.test(key));
  }

  private sanitizeString(str: string): string {
    // Remove potential script injection patterns
    const cleanStr = str
      // Remove null bytes and control characters
      // eslint-disable-next-line no-control-regex
      .replace(/[\x00-\x1f\x7f-\x9f]/g, '')
      // Remove potential script tags
      .replace(/<script[\s\S]*?<\/script>/gi, '')
      // Remove javascript: protocol
      .replace(/javascript:/gi, '')
      // Remove data: protocol with script content
      .replace(/data:.*script/gi, '')
      // Remove potential XSS vectors
      .replace(/on\w+\s*=/gi, '')
      // Limit string length to prevent DoS
      .substring(0, 10000);

    if (cleanStr !== str) {
      this.logger.warn('Potentially malicious string content sanitized', {
        originalLength: str.length,
        cleanedLength: cleanStr.length,
      });
    }

    return cleanStr;
  }

  private sanitizeNumber(num: number): number {
    // Check for dangerous number values
    if (!Number.isFinite(num) || Number.isNaN(num)) {
      this.logger.warn('Invalid number value detected, defaulting to 0');
      return 0;
    }

    // Prevent extremely large numbers that could cause overflow
    const MAX_SAFE_INTEGER = Number.MAX_SAFE_INTEGER;
    const MIN_SAFE_INTEGER = Number.MIN_SAFE_INTEGER;

    if (num > MAX_SAFE_INTEGER) {
      this.logger.warn('Number too large, capping to MAX_SAFE_INTEGER');
      return MAX_SAFE_INTEGER;
    }

    if (num < MIN_SAFE_INTEGER) {
      this.logger.warn('Number too small, capping to MIN_SAFE_INTEGER');
      return MIN_SAFE_INTEGER;
    }

    return num;
  }

  private validateNestingDepth(
    value: unknown,
    depth: number,
    maxDepth = 20,
  ): void {
    if (depth > maxDepth) {
      throw new BadRequestException({
        message: 'Input structure too deeply nested',
        maxAllowedDepth: maxDepth,
        currentDepth: depth,
      });
    }

    if (Array.isArray(value)) {
      value.forEach((item) =>
        this.validateNestingDepth(item, depth + 1, maxDepth),
      );
    } else if (value && typeof value === 'object' && value !== null) {
      Object.values(value as Record<string, unknown>).forEach((item) =>
        this.validateNestingDepth(item, depth + 1, maxDepth),
      );
    }
  }

  private validateCircularReferences(
    value: unknown,
    seen: WeakSet<object>,
  ): void {
    if (value && typeof value === 'object') {
      const objectValue = value;

      if (seen.has(objectValue)) {
        throw new BadRequestException({
          message: 'Circular reference detected in input',
          error: 'CIRCULAR_REFERENCE',
        });
      }

      seen.add(objectValue);

      if (Array.isArray(value)) {
        value.forEach((item) => this.validateCircularReferences(item, seen));
      } else {
        Object.values(value as Record<string, unknown>).forEach((item) =>
          this.validateCircularReferences(item, seen),
        );
      }

      seen.delete(objectValue);
    }
  }

  private validatePayloadSize(value: unknown): void {
    const MAX_PAYLOAD_SIZE = 1024 * 1024; // 1MB

    try {
      const serialized = JSON.stringify(value);
      const payloadSize = Buffer.byteLength(serialized, 'utf8');

      if (payloadSize > MAX_PAYLOAD_SIZE) {
        throw new BadRequestException({
          message: 'Payload size exceeds maximum allowed limit',
          maxSize: MAX_PAYLOAD_SIZE,
          actualSize: payloadSize,
        });
      }
    } catch (error) {
      if (error instanceof BadRequestException) {
        throw error;
      }
      // If JSON.stringify fails due to circular references or other issues
      throw new BadRequestException({
        message: 'Invalid payload structure',
        error: 'PAYLOAD_STRUCTURE_ERROR',
      });
    }
  }

  private getSafeInputDescription(value: unknown): string {
    try {
      if (Array.isArray(value)) {
        return `Array[${value.length}]`;
      }
      if (value && typeof value === 'object' && value !== null) {
        const keys = Object.keys(value as Record<string, unknown>);
        return `Object{${keys.join(', ')}}`;
      }
      if (typeof value === 'string') {
        return `String(${value.length} chars)`;
      }
      return typeof value;
    } catch {
      return 'unknown';
    }
  }
}
