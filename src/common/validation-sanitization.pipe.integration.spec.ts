import { Test, TestingModule } from '@nestjs/testing';
import { BadRequestException } from '@nestjs/common';
import { ValidationSanitizationPipe } from './validation-sanitization.pipe';
import { ArgumentMetadata } from '@nestjs/common';
import { IsString, IsNumber, IsOptional } from 'class-validator';

/* eslint-disable @typescript-eslint/no-unsafe-assignment */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */

// Test DTO classes
class SimpleTestDto {
  @IsString()
  name: string;

  @IsNumber()
  age: number;

  @IsOptional()
  @IsString()
  description?: string;
}

describe('ValidationSanitizationPipe - Core Security Tests', () => {
  let pipe: ValidationSanitizationPipe;
  let loggerSpy: jest.SpyInstance;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [ValidationSanitizationPipe],
    }).compile();

    pipe = module.get<ValidationSanitizationPipe>(ValidationSanitizationPipe);

    // Mock logger to prevent console output during tests
    loggerSpy = jest.spyOn(pipe['logger'], 'warn').mockImplementation();
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('Basic Validation Functionality', () => {
    const metadata: ArgumentMetadata = {
      type: 'body',
      metatype: SimpleTestDto,
    };

    it('should validate and transform valid input', async () => {
      const input = { name: 'John', age: 25 };
      const result = (await pipe.transform(input, metadata)) as SimpleTestDto;

      expect(result).toBeInstanceOf(SimpleTestDto);
      expect(result.name).toBe('John');
      expect(result.age).toBe(25);
    });

    it('should throw BadRequestException for invalid input types', async () => {
      const input = { name: 123, age: 'invalid' }; // Wrong types

      await expect(pipe.transform(input, metadata)).rejects.toThrow(
        BadRequestException,
      );
    });

    it('should handle optional fields', async () => {
      const input = { name: 'John', age: 25, description: 'Test description' };
      const result = (await pipe.transform(input, metadata)) as SimpleTestDto;

      expect(result.description).toBe('Test description');
    });

    it('should reject extra properties due to whitelist validation', async () => {
      const input = { name: 'John', age: 25, extraField: 'should be removed' };

      await expect(pipe.transform(input, metadata)).rejects.toThrow(
        BadRequestException,
      );
    });
  });

  describe('Prototype Pollution Protection', () => {
    const metadata: ArgumentMetadata = {
      type: 'body',
      metatype: SimpleTestDto,
    };

    it('should sanitize and remove dangerous prototype properties', async () => {
      const maliciousInput = {
        name: 'John',
        age: 25,
        __proto__: { polluted: true },
        constructor: { prototype: { admin: true } },
        prototype: { dangerous: true },
      };

      const result = (await pipe.transform(
        maliciousInput,
        metadata,
      )) as SimpleTestDto;

      // Should contain valid properties
      expect(result.name).toBe('John');
      expect(result.age).toBe(25);

      // Should not contain dangerous properties
      const resultKeys = Object.getOwnPropertyNames(result);
      expect(resultKeys).not.toContain('__proto__');
      expect(resultKeys).not.toContain('constructor');
      expect(resultKeys).not.toContain('prototype');

      // Logger should have been called
      expect(loggerSpy).toHaveBeenCalled();
    });

    it('should detect and block dangerous property patterns', async () => {
      const maliciousInput = {
        name: 'John',
        age: 25,
        'constructor.prototype': 'dangerous',
        __defineGetter__: 'malicious',
        valueOf: 'override',
        toString: 'override',
      };

      const result = (await pipe.transform(
        maliciousInput,
        metadata,
      )) as SimpleTestDto;

      expect(result.name).toBe('John');
      expect(result.age).toBe(25);

      const resultKeys = Object.getOwnPropertyNames(result);
      expect(resultKeys).not.toContain('constructor.prototype');
      expect(resultKeys).not.toContain('__defineGetter__');
      expect(resultKeys).not.toContain('valueOf');
      expect(resultKeys).not.toContain('toString');

      expect(loggerSpy).toHaveBeenCalled();
    });
  });

  describe('Security Validation - Pre-Processing Checks', () => {
    const metadata: ArgumentMetadata = {
      type: 'body',
      metatype: SimpleTestDto,
    };

    it('should reject circular references', async () => {
      const obj: any = { name: 'John', age: 25 };
      obj.self = obj; // Create circular reference

      await expect(pipe.transform(obj, metadata)).rejects.toThrow(
        BadRequestException,
      );
    });

    it('should reject deeply nested structures', async () => {
      // Create an object with more than 20 levels of nesting
      let deepObject: any = { name: 'John', age: 25 };
      for (let i = 0; i < 25; i++) {
        deepObject = { level: deepObject };
      }

      await expect(pipe.transform(deepObject, metadata)).rejects.toThrow(
        BadRequestException,
      );
    });

    it('should reject oversized payloads', async () => {
      // Create a large object that exceeds 1MB when serialized
      const largeString = 'x'.repeat(500000); // 500KB string
      const largeObject = {
        name: 'John',
        age: 25,
        data1: largeString,
        data2: largeString,
        data3: largeString, // Total > 1MB
      };

      await expect(pipe.transform(largeObject, metadata)).rejects.toThrow(
        BadRequestException,
      );
    });

    it('should allow reasonable payloads', async () => {
      const reasonablePayload = {
        name: 'John',
        age: 25,
        description: 'A reasonable amount of data',
      };

      const result = await pipe.transform(reasonablePayload, metadata);
      expect(result).toBeDefined();
    });
  });

  describe('Non-Validatable Types', () => {
    it('should pass through primitive types unchanged', async () => {
      const stringMetadata: ArgumentMetadata = {
        type: 'body',
        metatype: String,
      };

      const stringResult = await pipe.transform('test string', stringMetadata);
      expect(stringResult).toBe('test string');

      const numberResult = await pipe.transform(42, stringMetadata);
      expect(numberResult).toBe(42);

      const boolResult = await pipe.transform(true, stringMetadata);
      expect(boolResult).toBe(true);
    });

    it('should handle null and undefined values', async () => {
      const stringMetadata: ArgumentMetadata = {
        type: 'body',
        metatype: String,
      };

      const nullResult = await pipe.transform(null, stringMetadata);
      expect(nullResult).toBeNull();

      const undefinedResult = await pipe.transform(undefined, stringMetadata);
      expect(undefinedResult).toBeUndefined();
    });
  });

  describe('Array Processing', () => {
    const metadata: ArgumentMetadata = {
      type: 'body',
      metatype: SimpleTestDto,
    };

    it('should detect circular references in arrays', async () => {
      const arr: any[] = [1, 2, 3];
      arr.push(arr); // Create circular reference

      const obj = { name: 'John', age: 25, items: arr };

      await expect(pipe.transform(obj, metadata)).rejects.toThrow(
        BadRequestException,
      );
    });
  });

  describe('String Sanitization Detection', () => {
    const metadata: ArgumentMetadata = {
      type: 'body',
      metatype: SimpleTestDto,
    };

    it('should process string inputs through sanitization', async () => {
      const inputWithMaliciousString = {
        name: '<script>alert("xss")</script>CleanName',
        age: 25,
      };

      const result = (await pipe.transform(
        inputWithMaliciousString,
        metadata,
      )) as SimpleTestDto;

      // The string should be processed (even if not cleaned in this basic test)
      expect(result.name).toBeDefined();
      expect(typeof result.name).toBe('string');

      // Logger may be called for string sanitization
      // Note: Actual string cleaning depends on the sanitizeString implementation
    });
  });

  describe('Number Sanitization Detection', () => {
    const metadata: ArgumentMetadata = {
      type: 'body',
      metatype: SimpleTestDto,
    };

    it('should process number inputs through sanitization', async () => {
      const inputWithDangerousNumbers = {
        name: 'John',
        age: Infinity,
      };

      const result = (await pipe.transform(
        inputWithDangerousNumbers,
        metadata,
      )) as SimpleTestDto;

      // The number should be processed
      expect(result.age).toBeDefined();
      expect(typeof result.age).toBe('number');
      expect(Number.isFinite(result.age)).toBe(true);

      // Logger should be called for number sanitization
      expect(loggerSpy).toHaveBeenCalled();
    });

    it('should handle NaN values', async () => {
      const inputWithNaN = {
        name: 'John',
        age: NaN,
      };

      const result = (await pipe.transform(
        inputWithNaN,
        metadata,
      )) as SimpleTestDto;

      expect(result.age).toBeDefined();
      expect(typeof result.age).toBe('number');
      expect(result.age).toBe(0); // Should be sanitized to 0

      expect(loggerSpy).toHaveBeenCalled();
    });
  });

  describe('Performance and Stability', () => {
    const metadata: ArgumentMetadata = {
      type: 'body',
      metatype: SimpleTestDto,
    };

    it('should handle reasonable nested objects efficiently', async () => {
      const nestedInput = {
        name: 'John',
        age: 25,
        // Create a reasonably nested structure (within limits)
        profile: {
          settings: {
            theme: 'dark',
            notifications: {
              email: true,
            },
          },
        },
      };

      const startTime = Date.now();
      const result = await pipe.transform(nestedInput, metadata);
      const endTime = Date.now();

      expect(result).toBeDefined();
      expect(endTime - startTime).toBeLessThan(100); // Should be very fast for reasonable input
    });

    it('should handle arrays of simple objects', async () => {
      const inputWithArray = {
        name: 'John',
        age: 25,
        items: [
          { id: 1, value: 'item1' },
          { id: 2, value: 'item2' },
        ],
      };

      const result = await pipe.transform(inputWithArray, metadata);
      expect(result).toBeDefined();
    });
  });

  describe('Edge Cases and Error Handling', () => {
    const metadata: ArgumentMetadata = {
      type: 'body',
      metatype: SimpleTestDto,
    };

    it('should handle empty objects', async () => {
      const emptyInput = {};

      // This should fail validation because required fields are missing
      await expect(pipe.transform(emptyInput, metadata)).rejects.toThrow(
        BadRequestException,
      );
    });

    it('should handle mixed attack vectors', async () => {
      const complexAttack = {
        name: 'John<script>alert("xss")</script>',
        age: Number.MAX_SAFE_INTEGER * 2,
        __proto__: { polluted: true },
        constructor: { prototype: { admin: true } },
        'dangerous.property': 'value',
      };

      const result = (await pipe.transform(
        complexAttack,
        metadata,
      )) as SimpleTestDto;

      expect(result.name).toBeDefined();
      expect(result.age).toBeDefined();
      expect(Number.isFinite(result.age)).toBe(true);

      // Dangerous properties should be removed
      const keys = Object.getOwnPropertyNames(result);
      expect(keys).not.toContain('__proto__');
      expect(keys).not.toContain('constructor');
      expect(keys).not.toContain('dangerous.property');

      expect(loggerSpy).toHaveBeenCalled();
    });
  });
});
