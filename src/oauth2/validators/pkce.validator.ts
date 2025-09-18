import {
  registerDecorator,
  ValidationOptions,
  ValidationArguments,
  ValidatorConstraint,
  ValidatorConstraintInterface,
} from 'class-validator';

interface PKCEObject {
  code_challenge?: string;
  code_challenge_method?: string;
}

@ValidatorConstraint({ name: 'pkceConsistency', async: false })
export class PKCEConsistencyConstraint implements ValidatorConstraintInterface {
  validate(_value: unknown, args: ValidationArguments): boolean {
    const object = args.object as PKCEObject;
    const codeChallenge = object.code_challenge;
    const codeChallengeMethod = object.code_challenge_method;

    // 둘 다 있거나 둘 다 없어야 함
    const bothPresent = Boolean(codeChallenge && codeChallengeMethod);
    const bothAbsent = Boolean(!codeChallenge && !codeChallengeMethod);

    return bothPresent || bothAbsent;
  }

  defaultMessage(): string {
    return 'Both code_challenge and code_challenge_method must be provided together or both must be omitted';
  }
}

export function IsPKCEConsistent(validationOptions?: ValidationOptions) {
  return function (object: object, propertyName: string) {
    registerDecorator({
      target: object.constructor,
      propertyName: propertyName,
      options: validationOptions,
      constraints: [],
      validator: PKCEConsistencyConstraint,
    });
  };
}
