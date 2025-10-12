import { Test, TestingModule } from '@nestjs/testing';
import { BadRequestException } from '@nestjs/common';
import { ValidationSanitizationPipe } from './validation-sanitization.pipe';
import { ArgumentMetadata } from '@nestjs/common';
import { IsString, IsNumber, IsOptional } from 'class-validator';

/* eslint-disable @typescript-eslint/no-unsafe-assignment */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */

// Test DTO classes
class TestDto {
  @IsString()
  name: string;

  @IsNumber()
  age: number;

  @IsOptional()
  @IsString()
  description?: string;

  [key: string]: any; // Allow additional properties for testing
}

class NestedTestDto {
  @IsString()
  title: string;

  nested: TestDto;

  [key: string]: any; // Allow additional properties for testing
}

describe('ValidationSanitizationPipe', () => {
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

  describe('Basic Validation', () => {
    const metadata: ArgumentMetadata = {
      type: 'body',
      metatype: TestDto,
    };

    it('should validate and transform valid input', async () => {
      const input = { name: 'John', age: 25 };
      const result = (await pipe.transform(input, metadata)) as TestDto;

      expect(result).toBeInstanceOf(TestDto);
      expect(result.name).toBe('John');
      expect(result.age).toBe(25);
    });

    it('should throw BadRequestException for invalid input', async () => {
      const input = { name: 123, age: 'invalid' }; // Wrong types

      await expect(pipe.transform(input, metadata)).rejects.toThrow(
        BadRequestException,
      );
    });

    it('should handle optional fields correctly', async () => {
      const input = { name: 'John', age: 25, description: 'Test user' };
      const result = (await pipe.transform(input, metadata)) as TestDto;

      expect(result.description).toBe('Test user');
    });

    it('should return input unchanged for non-validatable metatypes', async () => {
      const stringMetadata: ArgumentMetadata = {
        type: 'body',
        metatype: String,
      };

      const input = 'test string';
      const result = (await pipe.transform(input, stringMetadata)) as string;

      expect(result).toBe(input);
    });
  });

  describe('Prototype Pollution Protection', () => {
    const metadata: ArgumentMetadata = {
      type: 'body',
      metatype: TestDto,
    };

    it('should remove dangerous properties from input', async () => {
      const maliciousInput = {
        name: 'John',
        age: 25,
        __proto__: { polluted: true },
        constructor: { prototype: { admin: true } },
        prototype: { polluted: true },
      };

      const result = await pipe.transform(maliciousInput, metadata);

      // The sanitized object should only contain valid properties
      expect(result.name).toBe('John');
      expect(result.age).toBe(25);

      // Dangerous properties should be removed
      const resultKeys = Object.getOwnPropertyNames(result);
      expect(resultKeys).not.toContain('__proto__');
      expect(resultKeys).not.toContain('constructor');
      expect(resultKeys).not.toContain('prototype');

      expect(loggerSpy).toHaveBeenCalled();
    });

    it('should handle string-based dangerous property names', async () => {
      const maliciousInput = {
        name: 'John',
        age: 25,
        'constructor.prototype': { polluted: true },
        __defineGetter__: 'malicious',
        valueOf: 'malicious',
      };

      const result = await pipe.transform(maliciousInput, metadata);

      expect(result.name).toBe('John');
      expect(result.age).toBe(25);

      const resultKeys = Object.getOwnPropertyNames(result);
      expect(resultKeys).not.toContain('constructor.prototype');
      expect(resultKeys).not.toContain('__defineGetter__');
      expect(resultKeys).not.toContain('valueOf');

      expect(loggerSpy).toHaveBeenCalled();
    });
  });

  describe('Nested Object Sanitization', () => {
    const metadata: ArgumentMetadata = {
      type: 'body',
      metatype: NestedTestDto,
    };

    it('should sanitize nested objects', async () => {
      const maliciousInput = {
        title: 'Test',
        nested: {
          name: 'John',
          age: 25,
          __proto__: { polluted: true },
        },
      };

      const result = await pipe.transform(maliciousInput, metadata);
      expect(result.nested).not.toHaveProperty('__proto__');
      expect(loggerSpy).toHaveBeenCalled();
    });

    it('should handle arrays with malicious objects', async () => {
      const maliciousInput: any = {
        title: 'Test',
        items: [
          { name: 'Item1', __proto__: { polluted: true } } as any,
          { name: 'Item2', constructor: { prototype: {} } } as any,
        ],
      };

      const result = await pipe.transform(maliciousInput, metadata);
      expect(result.items[0]).not.toHaveProperty('__proto__');
      expect(result.items[1]).not.toHaveProperty('constructor');
    });

    it('should handle deeply nested pollution attempts', async () => {
      const maliciousInput = {
        title: 'Test',
        level1: {
          level2: {
            level3: {
              __proto__: { polluted: true },
              name: 'deep',
            },
          },
        },
      };

      const result = await pipe.transform(maliciousInput, metadata);
      expect(result.level1.level2.level3).not.toHaveProperty('__proto__');
      expect(loggerSpy).toHaveBeenCalled();
    });
  });

  describe('String Sanitization', () => {
    const metadata: ArgumentMetadata = {
      type: 'body',
      metatype: TestDto,
    };

    it('should sanitize malicious script tags', async () => {
      const maliciousInput = {
        name: '<script>alert("xss")</script>John',
        age: 25,
      };

      const result = await pipe.transform(maliciousInput, metadata);
      expect(result.name).not.toContain('<script>');
      expect(loggerSpy).toHaveBeenCalled();
    });

    it('should remove javascript protocol', async () => {
      const maliciousInput = {
        name: 'javascript:alert("xss")John',
        age: 25,
      };

      const result = await pipe.transform(maliciousInput, metadata);
      expect(result.name).not.toContain('javascript:');
      expect(loggerSpy).toHaveBeenCalled();
    });

    it('should remove event handlers', async () => {
      const maliciousInput = {
        name: 'John onclick=alert("xss")',
        age: 25,
      };

      const result = await pipe.transform(maliciousInput, metadata);
      expect(result.name).not.toContain('onclick=');
      expect(loggerSpy).toHaveBeenCalled();
    });

    it('should limit string length to prevent DoS', async () => {
      const longString = 'a'.repeat(15000);
      const maliciousInput = {
        name: longString,
        age: 25,
      };

      const result = await pipe.transform(maliciousInput, metadata);
      expect(result.name.length).toBeLessThanOrEqual(10000);
      expect(loggerSpy).toHaveBeenCalled();
    });

    it('should remove control characters', async () => {
      const maliciousInput = {
        name: 'John\x00\x01\x1f\x7fDoe',
        age: 25,
      };

      const result = await pipe.transform(maliciousInput, metadata);
      expect(result.name).toBe('JohnDoe');
      expect(loggerSpy).toHaveBeenCalled();
    });
  });

  describe('Number Sanitization', () => {
    const metadata: ArgumentMetadata = {
      type: 'body',
      metatype: TestDto,
    };

    it('should sanitize NaN values', async () => {
      const maliciousInput = {
        name: 'John',
        age: NaN,
      };

      const result = await pipe.transform(maliciousInput, metadata);
      expect(result.age).toBe(0);
      expect(loggerSpy).toHaveBeenCalled();
    });

    it('should sanitize Infinity values', async () => {
      const maliciousInput = {
        name: 'John',
        age: Infinity,
      };

      const result = await pipe.transform(maliciousInput, metadata);
      expect(result.age).toBe(Number.MAX_SAFE_INTEGER);
      expect(loggerSpy).toHaveBeenCalled();
    });

    it('should sanitize negative Infinity', async () => {
      const maliciousInput = {
        name: 'John',
        age: -Infinity,
      };

      const result = await pipe.transform(maliciousInput, metadata);
      expect(result.age).toBe(Number.MIN_SAFE_INTEGER);
      expect(loggerSpy).toHaveBeenCalled();
    });

    it('should sanitize extremely large numbers', async () => {
      const maliciousInput = {
        name: 'John',
        age: Number.MAX_SAFE_INTEGER * 2, // This exceeds MAX_SAFE_INTEGER
      };

      const result = await pipe.transform(maliciousInput, metadata);
      expect(result.age).toBe(Number.MAX_SAFE_INTEGER);
      expect(loggerSpy).toHaveBeenCalled();
    });
  });

  describe('Nesting Depth Protection', () => {
    const metadata: ArgumentMetadata = {
      type: 'body',
      metatype: TestDto,
    };

    it('should reject deeply nested objects', async () => {
      // Create an object with 25 levels of nesting (exceeds the 20 limit)
      let deepObject: any = { name: 'John', age: 25 };
      for (let i = 0; i < 25; i++) {
        deepObject = { level: deepObject };
      }

      await expect(pipe.transform(deepObject, metadata)).rejects.toThrow(
        BadRequestException,
      );
    });

    it('should allow reasonable nesting depth', async () => {
      // Create an object with 10 levels of nesting (within the 20 limit)
      let reasonableObject: any = { name: 'John', age: 25 };
      for (let i = 0; i < 10; i++) {
        reasonableObject = { level: reasonableObject };
      }

      const result = await pipe.transform(reasonableObject, metadata);
      expect(result).toBeDefined();
    });
  });

  describe('Circular Reference Protection', () => {
    const metadata: ArgumentMetadata = {
      type: 'body',
      metatype: TestDto,
    };

    it('should detect and reject circular references in objects', async () => {
      const obj: any = { name: 'John', age: 25 };
      obj.self = obj; // Create circular reference

      await expect(pipe.transform(obj, metadata)).rejects.toThrow(
        BadRequestException,
      );
    });

    it('should detect circular references in nested arrays', async () => {
      const arr: any[] = [1, 2, 3];
      arr.push(arr); // Create circular reference in array

      const obj = { name: 'John', age: 25, items: arr };

      await expect(pipe.transform(obj, metadata)).rejects.toThrow(
        BadRequestException,
      );
    });

    it('should allow normal nested objects without circular references', async () => {
      const validInput = {
        name: 'John',
        age: 25,
        profile: {
          settings: {
            theme: 'dark',
          },
        },
      };

      const result = await pipe.transform(validInput, metadata);
      expect(result.name).toBe('John');
      expect(result.age).toBe(25);
    });
  });

  describe('Payload Size Protection', () => {
    const metadata: ArgumentMetadata = {
      type: 'body',
      metatype: TestDto,
    };

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

    it('should allow reasonable payload sizes', async () => {
      const reasonableObject = {
        name: 'John',
        age: 25,
        description: 'A reasonable amount of data',
      };

      const result = await pipe.transform(reasonableObject, metadata);
      expect(result).toBeDefined();
    });
  });

  describe('Edge Cases', () => {
    it('should return null for null input with non-validatable metatype', async () => {
      const nullMetadata: ArgumentMetadata = {
        type: 'body',
        metatype: String,
      };
      const result = await pipe.transform(null, nullMetadata);
      expect(result).toBeNull();
    });

    it('should return undefined for undefined input with non-validatable metatype', async () => {
      const undefinedMetadata: ArgumentMetadata = {
        type: 'body',
        metatype: String,
      };
      const result = await pipe.transform(undefined, undefinedMetadata);
      expect(result).toBeUndefined();
    });

    it('should handle primitive values correctly', async () => {
      const stringMetadata: ArgumentMetadata = {
        type: 'body',
        metatype: String,
      };

      const stringResult = await pipe.transform('test', stringMetadata);
      expect(stringResult).toBe('test');

      const numberResult = await pipe.transform(42, stringMetadata);
      expect(numberResult).toBe(42);
    });
  });

  describe('Complex Attack Scenarios', () => {
    const metadata: ArgumentMetadata = {
      type: 'body',
      metatype: TestDto,
    };

    it('should handle multiple simultaneous security issues', async () => {
      const complexAttack = {
        name: '<script>alert("xss")</script>John',
        age: Infinity,
        __proto__: { polluted: true },
        constructor: { prototype: { admin: true } },
      };

      const result = await pipe.transform(complexAttack, metadata);

      // Verify sanitization occurred
      expect(result.name).not.toContain('<script>');
      expect(result.age).toBe(Number.MAX_SAFE_INTEGER);

      // Check that dangerous properties were removed
      const keys = Object.getOwnPropertyNames(result);
      expect(keys).not.toContain('__proto__');
      expect(keys).not.toContain('constructor');

      expect(loggerSpy).toHaveBeenCalled();
    });

    it('should handle encoded dangerous patterns', async () => {
      const encodedAttack = {
        name: 'John',
        age: 25,
        '%5f%5fproto%5f%5f': { polluted: true },
      };

      const result = await pipe.transform(encodedAttack, metadata);
      const keys = Object.getOwnPropertyNames(result);
      expect(keys).not.toContain('%5f%5fproto%5f%5f');
      expect(loggerSpy).toHaveBeenCalled();
    });
  });
});
