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

    // Basic prototype pollution protection
    if (
      value &&
      typeof value === 'object' &&
      !Array.isArray(value) &&
      Object.prototype.toString.call(value) === '[object Object]'
    ) {
      // Check for dangerous properties using safer methods
      const dangerousKeys = ['__proto__', 'constructor', 'prototype'];
      const keys = Object.keys(value as Record<string, unknown>);
      const hasDangerousKey = dangerousKeys.some((key) => keys.includes(key));

      if (hasDangerousKey) {
        this.logger.warn('Potential prototype pollution attempt detected:', {
          input: this.getSafeInputDescription(value),
        });
        // Create a clean copy without dangerous properties
        const cleanValue: Record<string, unknown> = {};
        const sourceObject = value as Record<string, unknown>;
        for (const key of keys) {
          if (!dangerousKeys.includes(key)) {
            cleanValue[key] = sourceObject[key];
          }
        }
        value = cleanValue;
      }
    }

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
