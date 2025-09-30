import { Injectable, BadRequestException, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from '../../user/user.entity';
import { Client } from '../../client/client.entity';
import { AuthorizationCodeService } from '../authorization-code.service';
import { ScopeService } from '../scope.service';
import { AuthorizeRequestDto, AuthorizeResponseDto } from '../dto/oauth2.dto';
import {
  OAUTH2_CONSTANTS,
  OAUTH2_ERROR_MESSAGES,
} from '../../constants/oauth2.constants';

@Injectable()
export class AuthorizationService {
  private readonly logger = new Logger(AuthorizationService.name);

  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    @InjectRepository(Client)
    private readonly clientRepository: Repository<Client>,
    private readonly authCodeService: AuthorizationCodeService,
    private readonly scopeService: ScopeService,
  ) {}

  async validateAuthorizationRequest(
    authorizeDto: AuthorizeRequestDto,
  ): Promise<{ client: Client; requestedScopes: string[] }> {
    const { client_id, redirect_uri, response_type, scope, state } =
      authorizeDto;

    // Type validation
    if (typeof client_id !== 'string') {
      throw new BadRequestException(OAUTH2_ERROR_MESSAGES.INVALID_CLIENT_ID);
    }
    if (typeof redirect_uri !== 'string') {
      throw new BadRequestException(OAUTH2_ERROR_MESSAGES.INVALID_REDIRECT_URI);
    }
    if (typeof response_type !== 'string') {
      throw new BadRequestException(
        OAUTH2_ERROR_MESSAGES.INVALID_RESPONSE_TYPE,
      );
    }

    // Length validation for security
    if (client_id.length > OAUTH2_CONSTANTS.CLIENT_ID_MAX_LENGTH) {
      throw new BadRequestException('client_id parameter is too long');
    }
    if (redirect_uri.length > OAUTH2_CONSTANTS.REDIRECT_URI_MAX_LENGTH) {
      throw new BadRequestException('redirect_uri parameter is too long');
    }
    if (
      scope &&
      typeof scope === 'string' &&
      scope.length > OAUTH2_CONSTANTS.SCOPE_MAX_LENGTH
    ) {
      throw new BadRequestException('scope parameter is too long');
    }

    // Validate state parameter (REQUIRED for CSRF protection)
    if (!state || typeof state !== 'string' || state.length === 0) {
      throw new BadRequestException(OAUTH2_ERROR_MESSAGES.STATE_REQUIRED);
    }
    if (state.length > OAUTH2_CONSTANTS.STATE_MAX_LENGTH) {
      throw new BadRequestException('state parameter is too long');
    }

    // Validate response type
    if (response_type !== OAUTH2_CONSTANTS.SUPPORTED_RESPONSE_TYPE) {
      throw new BadRequestException(
        `Unsupported response type: ${response_type}`,
      );
    }

    // Validate client exists and is active
    const client = await this.clientRepository.findOne({
      where: { clientId: client_id, isActive: true },
    });
    if (!client) {
      throw new BadRequestException(OAUTH2_ERROR_MESSAGES.INVALID_CLIENT);
    }

    // Validate redirect URI matches client's registered URIs
    if (!client.redirectUris.includes(redirect_uri)) {
      throw new BadRequestException(OAUTH2_ERROR_MESSAGES.INVALID_REDIRECT_URI);
    }

    // Parse and validate scopes
    const requestedScopes = scope
      ? scope.split(' ').filter((s) => s.trim().length > 0)
      : [];

    // Validate scopes exist and are active
    if (requestedScopes.length > 0) {
      const validScopes =
        await this.scopeService.validateScopes(requestedScopes);
      if (!validScopes) {
        throw new BadRequestException('Invalid scope(s) requested');
      }
    }

    return { client, requestedScopes };
  }

  async authorize(
    authorizeDto: AuthorizeRequestDto,
    user: User,
  ): Promise<AuthorizeResponseDto> {
    // 먼저 검증 수행
    const { client, requestedScopes } =
      await this.validateAuthorizationRequest(authorizeDto);

    const { redirect_uri, state, code_challenge, code_challenge_method } =
      authorizeDto;

    // PKCE 파라미터 검증 (OPTIONAL but RECOMMENDED for security)
    if (code_challenge || code_challenge_method) {
      this.validatePKCEParameters(code_challenge, code_challenge_method);
    }

    // If only one PKCE parameter is provided, require both
    if (
      (code_challenge && !code_challenge_method) ||
      (!code_challenge && code_challenge_method)
    ) {
      throw new BadRequestException(
        'Both code_challenge and code_challenge_method must be provided together',
      );
    }

    // Generate authorization code
    const authCode = await this.authCodeService.createAuthorizationCode(
      user,
      client,
      redirect_uri,
      requestedScopes,
      typeof state === 'string' ? state : undefined,
      typeof code_challenge === 'string' ? code_challenge : undefined,
      typeof code_challenge_method === 'string'
        ? code_challenge_method
        : undefined,
    );
    this.logger.log(`Authorization code created: ${authCode.code}`);

    return {
      code: authCode.code,
      state: typeof state === 'string' ? state : undefined,
      redirect_uri,
    };
  }

  private validatePKCEParameters(
    codeChallenge?: string,
    codeChallengeMethod?: string,
  ): void {
    // PKCE is OPTIONAL but RECOMMENDED for security (RFC 7636)
    if (codeChallenge) {
      // Validate code challenge format (base64url encoded)
      const base64UrlRegex = /^[A-Za-z0-9\-_]+$/;
      if (!base64UrlRegex.test(codeChallenge)) {
        throw new BadRequestException('Invalid code_challenge format');
      }

      // Validate code challenge length (43-128 characters for SHA256)
      if (codeChallenge.length < 43 || codeChallenge.length > 128) {
        throw new BadRequestException('Invalid code_challenge length');
      }
    }

    if (codeChallengeMethod) {
      // Only S256 is supported (SHA256)
      if (codeChallengeMethod !== 'S256') {
        throw new BadRequestException(
          'Only S256 code_challenge_method is supported',
        );
      }
    }
  }
}
