import {
  registerDecorator,
  ValidationOptions,
  ValidationArguments,
  ValidatorConstraint,
  ValidatorConstraintInterface,
} from 'class-validator';

interface TokenRequestObject {
  grant_type: string;
  client_id?: string;
  code?: string;
  redirect_uri?: string;
  refresh_token?: string;
  code_verifier?: string;
}

@ValidatorConstraint({ name: 'grantTypeRequiredFields', async: false })
export class GrantTypeRequiredFieldsConstraint
  implements ValidatorConstraintInterface
{
  validate(_value: unknown, args: ValidationArguments): boolean {
    const object = args.object as TokenRequestObject;
    const { grant_type } = object;

    switch (grant_type) {
      case 'authorization_code':
        // authorization_code grant requires: client_id, code, redirect_uri
        return Boolean(object.client_id && object.code && object.redirect_uri);

      case 'refresh_token':
        // refresh_token grant requires: client_id, refresh_token
        return Boolean(object.client_id && object.refresh_token);

      case 'client_credentials':
        // client_credentials grant requires: client_id
        return Boolean(object.client_id);

      default:
        return false; // Unsupported grant type
    }
  }

  defaultMessage(args: ValidationArguments): string {
    const object = args.object as TokenRequestObject;
    const { grant_type } = object;

    switch (grant_type) {
      case 'authorization_code':
        return 'For authorization_code grant, client_id, code, and redirect_uri are required';
      case 'refresh_token':
        return 'For refresh_token grant, client_id and refresh_token are required';
      case 'client_credentials':
        return 'For client_credentials grant, client_id is required';
      default:
        return 'Invalid grant_type or missing required fields';
    }
  }
}

export function IsValidGrantTypeFields(validationOptions?: ValidationOptions) {
  return function (object: object, propertyName: string) {
    registerDecorator({
      target: object.constructor,
      propertyName: propertyName,
      options: validationOptions,
      constraints: [],
      validator: GrantTypeRequiredFieldsConstraint,
    });
  };
}
