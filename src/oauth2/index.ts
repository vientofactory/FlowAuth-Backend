// OAuth2 Guards
export { OAuth2BearerGuard } from './oauth2-bearer.guard';
export { OAuth2ScopeGuard } from './guards/oauth2-scope.guard';

// OAuth2 Decorators
export {
  RequireScopes,
  RequireAnyScope,
  RequireAllScopes,
} from './decorators/require-scopes.decorator';

// OAuth2 Services
export { OAuth2Service } from './oauth2.service';
export { TokenService } from './token.service';
export { ScopeService } from './scope.service';
export { AuthorizationCodeService } from './authorization-code.service';

// OAuth2 Types
export type {
  OAuth2JwtPayload,
  OAuth2AuthenticatedRequest,
  ScopeDefinition,
  IntrospectionResponse,
  OAuth2ErrorResponse,
  ScopeValidationResult,
  TokenMetadata,
} from '../types/oauth2.types';

// OAuth2 Constants
export {
  OAUTH2_SCOPES,
  SCOPE_DESCRIPTIONS,
  DEFAULT_SCOPES,
} from '../constants/oauth2.constants';

// OAuth2 Module
export { OAuth2Module } from './oauth2.module';
