import { Logger } from '@nestjs/common';

/**
 * Development-only logging utility
 */
export class DevelopmentLogger {
  private readonly logger: Logger;
  private readonly isDevelopment: boolean;
  private readonly isTest: boolean;

  constructor(context: string) {
    this.logger = new Logger(context);
    this.isDevelopment = process.env.NODE_ENV === 'development';
    this.isTest = process.env.NODE_ENV === 'test';
  }

  devLog(message: string, context?: string): void {
    if (this.isDevelopment) {
      this.logger.log(message, context);
    }
  }

  devDebug(message: string, context?: string): void {
    if (this.isDevelopment) {
      this.logger.debug(message, context);
    }
  }

  devVerbose(message: string, context?: string): void {
    if (this.isDevelopment) {
      this.logger.verbose(message, context);
    }
  }

  warn(message: string, trace?: string, context?: string): void {
    this.logger.warn(message, trace, context);
  }

  error(message: string, trace?: string, context?: string): void {
    this.logger.error(message, trace, context);
  }

  log(message: string, context?: string): void {
    this.logger.log(message, context);
  }

  devLogObject(label: string, obj: unknown): void {
    if (this.isDevelopment) {
      this.logger.log(`${label}: ${JSON.stringify(obj, null, 2)}`);
    }
  }

  devOnly(fn: () => void): void {
    if (this.isDevelopment) {
      try {
        fn();
      } catch (error) {
        this.logger.warn(`Development-only function failed: ${error}`);
      }
    }
  }

  conditionalLog(message: string, force = false, context?: string): void {
    if (this.isDevelopment || force) {
      this.logger.log(message, context);
    }
  }

  nonTestLog(message: string, context?: string): void {
    if (!this.isTest) {
      this.logger.log(message, context);
    }
  }

  getEnvironmentInfo(): {
    isDevelopment: boolean;
    isTest: boolean;
    nodeEnv: string | undefined;
  } {
    return {
      isDevelopment: this.isDevelopment,
      isTest: this.isTest,
      nodeEnv: process.env.NODE_ENV,
    };
  }
}

export function createDevelopmentLogger(context: string): DevelopmentLogger {
  return new DevelopmentLogger(context);
}

export function isDevelopmentEnvironment(): boolean {
  return process.env.NODE_ENV === 'development';
}

export function isProductionEnvironment(): boolean {
  return process.env.NODE_ENV === 'production';
}
