import { LoggingService } from '../services/logging.service';

export interface CatchExceptionsOptions {
  logError?: boolean;
  rethrow?: boolean;
  context?: string;
}

export function CatchExceptions(options: CatchExceptionsOptions = {}) {
  const { logError = true, rethrow = true, context } = options;

  return function (
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    target: any,
    propertyKey: string | symbol,
    descriptor: PropertyDescriptor,
  ) {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
    const method = descriptor.value;
    // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
    const methodName = `${target.constructor.name}.${String(propertyKey)}`;
    const logContext = context ?? methodName;

    descriptor.value = async function (...args: unknown[]) {
      try {
        // eslint-disable-next-line @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-return
        return await method.apply(this, args);
      } catch (error) {
        if (logError) {
          LoggingService.logError(logContext, error, {
            method: String(propertyKey),
            args: args.length,
          });
        }

        if (rethrow) {
          throw error;
        }

        return undefined;
      }
    };

    return descriptor;
  };
}
