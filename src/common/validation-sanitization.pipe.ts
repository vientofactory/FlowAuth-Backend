import {
  Injectable,
  PipeTransform,
  ArgumentMetadata,
  BadRequestException,
} from '@nestjs/common';
import { validate, ValidationError } from 'class-validator';
import { plainToClass } from 'class-transformer';
import { sanitize } from 'class-sanitizer';

@Injectable()
export class ValidationSanitizationPipe implements PipeTransform<any> {
  async transform(value: any, { metatype }: ArgumentMetadata): Promise<any> {
    if (!metatype || !this.toValidate(metatype)) {
      return value;
    }

    // Sanitize input only if it's a valid object
    if (
      value &&
      typeof value === 'object' &&
      Object.prototype.toString.call(value) === '[object Object]'
    ) {
      try {
        sanitize(value);
      } catch {
        // If sanitization fails, continue without sanitization
        // This prevents crashes from malformed input
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
}
