import {
  registerDecorator,
  ValidationOptions,
  ValidationArguments,
  ValidatorConstraint,
  ValidatorConstraintInterface,
} from 'class-validator';
import { OAUTH2_CONSTANTS } from '../../constants/oauth2.constants';

interface PKCEFormatObject {
  code_challenge?: string;
  code_challenge_method?: string;
}

@ValidatorConstraint({ name: 'pkceFormat', async: false })
export class PKCEFormatConstraint implements ValidatorConstraintInterface {
  validate(_value: unknown, args: ValidationArguments): boolean {
    const object = args.object as PKCEFormatObject;
    const { code_challenge, code_challenge_method } = object;

    // If neither is provided, it's valid (PKCE is optional)
    if (!code_challenge && !code_challenge_method) {
      return true;
    }

    // If only one is provided, it's invalid (handled by PKCEConsistencyConstraint)
    if (!code_challenge || !code_challenge_method) {
      return false;
    }

    // Validate based on method
    if (code_challenge_method === 'S256') {
      // Base64url encoded SHA256 hash should be exactly 43 characters and valid format
      return (
        code_challenge.length === OAUTH2_CONSTANTS.CODE_CHALLENGE_S256_LENGTH &&
        OAUTH2_CONSTANTS.CODE_CHALLENGE_S256_PATTERN.test(code_challenge)
      );
    } else if (code_challenge_method === 'plain') {
      // Plain method should be 43-128 characters and valid format
      return (
        code_challenge.length >=
          OAUTH2_CONSTANTS.CODE_CHALLENGE_PLAIN_MIN_LENGTH &&
        code_challenge.length <=
          OAUTH2_CONSTANTS.CODE_CHALLENGE_PLAIN_MAX_LENGTH &&
        OAUTH2_CONSTANTS.PKCE_UNRESERVED_CHAR_PATTERN.test(code_challenge)
      );
    }

    return false; // Invalid method
  }

  defaultMessage(args: ValidationArguments): string {
    const object = args.object as PKCEFormatObject;
    const { code_challenge_method } = object;

    if (code_challenge_method === 'S256') {
      return `code_challenge for S256 method must be exactly ${OAUTH2_CONSTANTS.CODE_CHALLENGE_S256_LENGTH} characters and base64url-encoded`;
    } else if (code_challenge_method === 'plain') {
      return `code_challenge for plain method must be between ${OAUTH2_CONSTANTS.CODE_CHALLENGE_PLAIN_MIN_LENGTH} and ${OAUTH2_CONSTANTS.CODE_CHALLENGE_PLAIN_MAX_LENGTH} characters`;
    }

    return 'Invalid PKCE format for the specified method';
  }
}

export function IsValidPKCEFormat(validationOptions?: ValidationOptions) {
  return function (object: object, propertyName: string) {
    registerDecorator({
      target: object.constructor,
      propertyName: propertyName,
      options: validationOptions,
      constraints: [],
      validator: PKCEFormatConstraint,
    });
  };
}
