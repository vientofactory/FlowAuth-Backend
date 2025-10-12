import { Injectable, BadRequestException, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from '../../auth/user.entity';
import { Client } from '../client.entity';
import { AuthorizationCodeService } from '../authorization-code.service';
import { TokenService } from '../token.service';
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
    private readonly tokenService: TokenService,
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

    // Validate state parameter (RECOMMENDED for CSRF protection)
    if (state && typeof state === 'string') {
      if (state.length > OAUTH2_CONSTANTS.STATE_MAX_LENGTH) {
        throw new BadRequestException('state parameter is too long');
      }
    }

    // Validate nonce parameter (OIDC)
    if (authorizeDto.nonce && typeof authorizeDto.nonce === 'string') {
      if (authorizeDto.nonce.length > OAUTH2_CONSTANTS.NONCE_MAX_LENGTH) {
        throw new BadRequestException('nonce parameter is too long');
      }
    }

    // Validate response type
    const validResponseTypes = OAUTH2_CONSTANTS.SUPPORTED_RESPONSE_TYPES;
    if (
      !validResponseTypes.includes(
        response_type as (typeof validResponseTypes)[number],
      )
    ) {
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

    // 레거시 스코프들을 새로운 스코프들로 정규화
    const normalizedScopes = this.scopeService.normalizeScopes(requestedScopes);

    return { client, requestedScopes: normalizedScopes };
  }

  async authorize(
    authorizeDto: AuthorizeRequestDto,
    user: User,
  ): Promise<AuthorizeResponseDto> {
    // 먼저 검증 수행
    const { client, requestedScopes } =
      await this.validateAuthorizationRequest(authorizeDto);

    const {
      redirect_uri,
      response_type,
      state,
      code_challenge,
      code_challenge_method,
      nonce,
    } = authorizeDto;

    // response_type에 따른 처리
    if (response_type === OAUTH2_CONSTANTS.RESPONSE_TYPES.CODE) {
      // Authorization Code Grant
      return this.handleAuthorizationCodeGrant(
        user,
        client,
        requestedScopes,
        redirect_uri,
        state,
        code_challenge,
        code_challenge_method,
        nonce,
      );
    } else if (
      response_type === OAUTH2_CONSTANTS.RESPONSE_TYPES.CODE_ID_TOKEN
    ) {
      // Hybrid Flow (Authorization Code + ID Token)
      return this.handleHybridGrant(
        user,
        client,
        requestedScopes,
        redirect_uri,
        state,
        code_challenge,
        code_challenge_method,
        nonce,
      );
    } else if (
      response_type === OAUTH2_CONSTANTS.RESPONSE_TYPES.TOKEN ||
      response_type === OAUTH2_CONSTANTS.RESPONSE_TYPES.ID_TOKEN ||
      response_type === OAUTH2_CONSTANTS.RESPONSE_TYPES.TOKEN_ID_TOKEN
    ) {
      // Implicit Grant (OAuth2 및 OpenID Connect)
      return this.handleImplicitGrant(
        user,
        client,
        requestedScopes,
        redirect_uri,
        response_type,
        state,
        nonce,
      );
    } else {
      throw new BadRequestException(
        `Unsupported response_type: ${response_type}`,
      );
    }
  }

  private async handleAuthorizationCodeGrant(
    user: User,
    client: Client,
    requestedScopes: string[],
    redirectUri: string,
    state?: string,
    codeChallenge?: string,
    codeChallengeMethod?: string,
    nonce?: string,
  ): Promise<AuthorizeResponseDto> {
    // PKCE 파라미터 검증 (OPTIONAL but RECOMMENDED for security)
    if (codeChallenge || codeChallengeMethod) {
      this.validatePKCEParameters(codeChallenge, codeChallengeMethod);
    }

    // If only one PKCE parameter is provided, require both
    if (
      (codeChallenge && !codeChallengeMethod) ||
      (!codeChallenge && codeChallengeMethod)
    ) {
      throw new BadRequestException(
        'Both code_challenge and code_challenge_method must be provided together',
      );
    }

    // Generate authorization code
    const authCode = await this.authCodeService.createAuthorizationCode(
      user,
      client,
      redirectUri,
      requestedScopes,
      state,
      codeChallenge,
      codeChallengeMethod,
      nonce,
    );
    this.logger.log(`Authorization code created: ${authCode.code}`);

    return {
      code: authCode.code,
      state,
      redirect_uri: redirectUri,
    };
  }

  private async handleHybridGrant(
    user: User,
    client: Client,
    requestedScopes: string[],
    redirectUri: string,
    state?: string,
    codeChallenge?: string,
    codeChallengeMethod?: string,
    nonce?: string,
  ): Promise<AuthorizeResponseDto> {
    // Hybrid Flow에서는 PKCE를 사용할 수 있음
    if (codeChallenge || codeChallengeMethod) {
      this.validatePKCEParameters(codeChallenge, codeChallengeMethod);
    }

    // If only one PKCE parameter is provided, require both
    if (
      (codeChallenge && !codeChallengeMethod) ||
      (!codeChallenge && codeChallengeMethod)
    ) {
      throw new BadRequestException(
        'Both code_challenge and code_challenge_method must be provided together',
      );
    }

    // Hybrid Flow에서는 openid scope가 필수
    if (!requestedScopes.includes('openid')) {
      throw new BadRequestException(
        'response_type=code id_token requires openid scope',
      );
    }

    // Generate authorization code
    const authCode = await this.authCodeService.createAuthorizationCode(
      user,
      client,
      redirectUri,
      requestedScopes,
      state,
      codeChallenge,
      codeChallengeMethod,
      nonce,
    );
    this.logger.log(
      `Authorization code created for hybrid flow: ${authCode.code}`,
    );

    // Generate ID token for immediate response
    const tokens = await this.tokenService.createImplicitTokens(
      user,
      client,
      requestedScopes,
      nonce,
    );

    return {
      code: authCode.code,
      id_token: tokens.idToken,
      state,
      redirect_uri: redirectUri,
    };
  }

  private async handleImplicitGrant(
    user: User,
    client: Client,
    requestedScopes: string[],
    redirect_uri: string,
    response_type: string,
    state?: string,
    nonce?: string,
  ): Promise<AuthorizeResponseDto> {
    // Implicit Grant을 위한 토큰 생성
    const implicitTokens = await this.tokenService.createImplicitTokens(
      user,
      client,
      requestedScopes,
      nonce,
    );

    const response: AuthorizeResponseDto = {
      redirect_uri,
    };

    // response_type에 따라 토큰 결정
    if (
      response_type === OAUTH2_CONSTANTS.RESPONSE_TYPES.TOKEN ||
      response_type === OAUTH2_CONSTANTS.RESPONSE_TYPES.TOKEN_ID_TOKEN
    ) {
      response.access_token = implicitTokens.accessToken;
      response.token_type = implicitTokens.tokenType;
      response.expires_in = implicitTokens.expiresIn;
    }

    if (
      response_type === OAUTH2_CONSTANTS.RESPONSE_TYPES.ID_TOKEN ||
      response_type === OAUTH2_CONSTANTS.RESPONSE_TYPES.TOKEN_ID_TOKEN
    ) {
      if (!nonce) {
        throw new BadRequestException(
          'nonce is required for OpenID Connect implicit flow',
        );
      }
      response.id_token = implicitTokens.idToken;
    }

    if (state) {
      response.state = state;
    }

    return response;
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

  async getConsentInfo(
    authorizeDto: AuthorizeRequestDto,
  ): Promise<{ client: Client; scopes: string[] }> {
    const { client_id, redirect_uri, scope } = authorizeDto;

    // Find and validate client
    const client = await this.clientRepository.findOne({
      where: { clientId: client_id, isActive: true },
    });

    if (!client) {
      throw new BadRequestException('Invalid client_id');
    }

    // Validate redirect URI
    if (!client.redirectUris.includes(redirect_uri)) {
      throw new BadRequestException('Invalid redirect_uri');
    }

    // Parse and validate scopes
    const scopeValue = typeof scope === 'string' ? scope : '';
    const requestedScopes = scopeValue ? scopeValue.split(' ') : [];

    return {
      client,
      scopes: requestedScopes,
    };
  }
}
