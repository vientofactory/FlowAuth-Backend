import {
  Injectable,
  BadRequestException,
  UnauthorizedException,
  Logger,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from '../user/user.entity';
import { Client } from '../client/client.entity';
import { AuthorizationCodeService } from './authorization-code.service';
import { TokenService } from './token.service';
import { ScopeService } from './scope.service';
import {
  AuthorizeRequestDto,
  TokenRequestDto,
  AuthorizeResponseDto,
  TokenResponseDto,
} from './dto/oauth2.dto';
import {
  OAUTH2_CONSTANTS,
  RATE_LIMIT_CONSTANTS,
  OAUTH2_ERROR_MESSAGES,
} from '../constants/oauth2.constants';

@Injectable()
export class OAuth2Service {
  private readonly logger = new Logger(OAuth2Service.name);

  // Rate limiting configuration
  private rateLimitStore = new Map<
    string,
    { count: number; resetTime: number }
  >();

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

    // Rate limiting check
    if (!this.checkRateLimit(`auth:${client_id}`)) {
      throw new BadRequestException(OAUTH2_ERROR_MESSAGES.RATE_LIMIT_EXCEEDED);
    }

    // Clean up old rate limit records periodically
    this.cleanupRateLimitStore();

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

    // Find and validate client
    const client = await this.clientRepository.findOne({
      where: { clientId: client_id, isActive: true },
    });

    if (!client) {
      throw new BadRequestException(OAUTH2_ERROR_MESSAGES.INVALID_CLIENT);
    }

    // Validate redirect URI
    const sanitizedRedirectUri = this.sanitizeRedirectUri(redirect_uri);
    if (!sanitizedRedirectUri) {
      throw new BadRequestException(
        OAUTH2_ERROR_MESSAGES.INVALID_REDIRECT_URI_FORMAT,
      );
    }

    // Validate redirect URI against client's registered URIs
    if (!this.isValidRedirectUri(sanitizedRedirectUri, client.redirectUris)) {
      throw new BadRequestException(
        OAUTH2_ERROR_MESSAGES.INVALID_REDIRECT_URI_CLIENT,
      );
    }

    // Validate scopes
    const scopeValue = typeof scope === 'string' ? scope : '';
    const requestedScopes = scopeValue ? scopeValue.split(' ') : [];
    const validScopes = await this.scopeService.validateScopes(requestedScopes);

    if (!validScopes && requestedScopes.length > 0) {
      throw new BadRequestException(OAUTH2_ERROR_MESSAGES.INVALID_SCOPE);
    }

    // Validate client-specific scopes
    if (!this.validateClientScopes(client, requestedScopes)) {
      throw new BadRequestException(
        'Client is not authorized for requested scopes',
      );
    }

    return {
      client,
      requestedScopes,
    };
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
    if (codeChallenge || codeChallengeMethod) {
      this.validatePKCEChallengeAndMethod(codeChallenge, codeChallengeMethod);
      this.validatePKCEChallengeFormat(codeChallenge!, codeChallengeMethod!);
    }
  }

  private validatePKCEChallengeAndMethod(
    codeChallenge?: string,
    codeChallengeMethod?: string,
  ): void {
    if (!codeChallenge) {
      throw new BadRequestException(
        OAUTH2_ERROR_MESSAGES.PKCE_CHALLENGE_MISSING,
      );
    }
    if (!codeChallengeMethod) {
      throw new BadRequestException(OAUTH2_ERROR_MESSAGES.PKCE_METHOD_MISSING);
    }
    if (!OAUTH2_CONSTANTS.PKCE_METHODS.includes(codeChallengeMethod as never)) {
      throw new BadRequestException(
        `${OAUTH2_ERROR_MESSAGES.INVALID_PKCE_METHOD}: ${codeChallengeMethod}. Supported methods are 'plain' and 'S256'`,
      );
    }
  }

  private validatePKCEChallengeFormat(
    codeChallenge: string,
    codeChallengeMethod: string,
  ): void {
    if (codeChallengeMethod === 'S256') {
      // Base64url encoded SHA256 hash should be exactly 43 characters and valid format
      if (
        codeChallenge.length !== OAUTH2_CONSTANTS.CODE_CHALLENGE_S256_LENGTH ||
        !OAUTH2_CONSTANTS.CODE_CHALLENGE_S256_PATTERN.test(codeChallenge)
      ) {
        throw new BadRequestException(
          OAUTH2_ERROR_MESSAGES.INVALID_PKCE_FORMAT_S256,
        );
      }
    } else if (codeChallengeMethod === 'plain') {
      // Plain method should be 43-128 characters and valid format
      if (
        codeChallenge.length <
          OAUTH2_CONSTANTS.CODE_CHALLENGE_PLAIN_MIN_LENGTH ||
        codeChallenge.length >
          OAUTH2_CONSTANTS.CODE_CHALLENGE_PLAIN_MAX_LENGTH ||
        !OAUTH2_CONSTANTS.PKCE_UNRESERVED_CHAR_PATTERN.test(codeChallenge)
      ) {
        throw new BadRequestException(
          OAUTH2_ERROR_MESSAGES.INVALID_PKCE_LENGTH_PLAIN,
        );
      }
    }
  }

  async token(tokenDto: TokenRequestDto): Promise<TokenResponseDto> {
    const { grant_type, client_id } = tokenDto;

    // Rate limiting check for token requests (stricter limits)
    if (
      client_id &&
      !this.checkRateLimit(
        `token:${client_id}`,
        RATE_LIMIT_CONSTANTS.MAX_TOKEN_REQUESTS,
      )
    ) {
      throw new BadRequestException(
        OAUTH2_ERROR_MESSAGES.TOKEN_RATE_LIMIT_EXCEEDED,
      );
    }

    // Clean up old rate limit records periodically
    this.cleanupRateLimitStore();

    // Type validation
    if (typeof grant_type !== 'string') {
      throw new BadRequestException('Invalid grant_type parameter');
    }

    if (!OAUTH2_CONSTANTS.SUPPORTED_GRANT_TYPES.includes(grant_type as never)) {
      throw new BadRequestException(`Unsupported grant type: ${grant_type}`);
    }

    switch (grant_type) {
      case 'authorization_code':
        return this.handleAuthorizationCodeGrant(tokenDto);
      case 'refresh_token':
        return this.handleRefreshTokenGrant(tokenDto);
      case 'client_credentials':
        return this.handleClientCredentialsGrant(tokenDto);
      default:
        throw new BadRequestException(`Unsupported grant type: ${grant_type}`);
    }
  }

  private async handleAuthorizationCodeGrant(
    tokenDto: TokenRequestDto,
  ): Promise<TokenResponseDto> {
    const { client_id, client_secret, code, redirect_uri, code_verifier } =
      tokenDto;

    // Type validation
    if (typeof client_id !== 'string') {
      throw new BadRequestException('Invalid client_id parameter');
    }
    if (typeof code !== 'string') {
      throw new BadRequestException('Invalid code parameter');
    }

    // Length validation
    if (client_id.length > OAUTH2_CONSTANTS.CLIENT_ID_MAX_LENGTH) {
      throw new BadRequestException('client_id parameter is too long');
    }
    if (code.length > OAUTH2_CONSTANTS.AUTHORIZATION_CODE_MAX_LENGTH) {
      // Authorization code length limit
      throw new BadRequestException('code parameter is too long');
    }
    if (
      redirect_uri &&
      typeof redirect_uri === 'string' &&
      redirect_uri.length > OAUTH2_CONSTANTS.REDIRECT_URI_MAX_LENGTH
    ) {
      throw new BadRequestException('redirect_uri parameter is too long');
    }
    if (
      code_verifier &&
      typeof code_verifier === 'string' &&
      code_verifier.length > OAUTH2_CONSTANTS.CODE_VERIFIER_MAX_LENGTH
    ) {
      // PKCE verifier max length
      throw new BadRequestException('code_verifier parameter is too long');
    }

    const client = await this.validateClient(client_id, client_secret);

    // Validate and consume authorization code
    const authCode = await this.authCodeService.validateAndConsumeCode(
      code,
      client_id,
      typeof redirect_uri === 'string' ? redirect_uri : undefined,
      typeof code_verifier === 'string' ? code_verifier : undefined,
    );

    if (!authCode) {
      throw new BadRequestException('Invalid authorization code');
    }

    // Create token
    const tokenResponse = await this.tokenService.createToken(
      authCode.user,
      client,
      authCode.scopes,
    );

    return {
      access_token: tokenResponse.accessToken,
      token_type: tokenResponse.tokenType,
      expires_in: tokenResponse.expiresIn,
      refresh_token: tokenResponse.refreshToken,
      scope: authCode.scopes?.join(' ') || '',
    };
  }

  private async handleRefreshTokenGrant(
    tokenDto: TokenRequestDto,
  ): Promise<TokenResponseDto> {
    const { refresh_token, client_id, client_secret } = tokenDto;

    // Type validation
    if (typeof refresh_token !== 'string') {
      throw new BadRequestException('Invalid refresh_token parameter');
    }
    if (typeof client_id !== 'string') {
      throw new BadRequestException('Invalid client_id parameter');
    }

    // Length validation
    if (refresh_token.length > OAUTH2_CONSTANTS.REFRESH_TOKEN_MAX_LENGTH) {
      // Refresh token length limit
      throw new BadRequestException('refresh_token parameter is too long');
    }
    if (client_id.length > OAUTH2_CONSTANTS.CLIENT_ID_MAX_LENGTH) {
      throw new BadRequestException('client_id parameter is too long');
    }

    await this.validateClient(client_id, client_secret);

    // Log refresh token request for security monitoring
    this.logger.log(
      `Refresh token request from client ${client_id} for user token`,
    );

    // Refresh token
    const tokenResponse = await this.tokenService.refreshToken(
      refresh_token,
      client_id,
    );

    if (!tokenResponse) {
      this.logger.warn(
        `Invalid refresh token attempt from client ${client_id}`,
      );
      throw new BadRequestException('Invalid refresh token');
    }

    this.logger.log(
      `Refresh token successfully renewed for client ${client_id}`,
    );

    return {
      access_token: tokenResponse.accessToken,
      token_type: tokenResponse.tokenType,
      expires_in: tokenResponse.expiresIn,
      refresh_token: tokenResponse.refreshToken,
      scope: tokenResponse.scopes?.join(' ') || '',
    };
  }

  private async handleClientCredentialsGrant(
    tokenDto: TokenRequestDto,
  ): Promise<TokenResponseDto> {
    const { client_id, client_secret, scope } = tokenDto;

    // Type validation
    if (typeof client_id !== 'string') {
      throw new BadRequestException('Invalid client_id parameter');
    }

    // Length validation
    if (client_id.length > OAUTH2_CONSTANTS.CLIENT_ID_MAX_LENGTH) {
      throw new BadRequestException('client_id parameter is too long');
    }
    if (
      scope &&
      typeof scope === 'string' &&
      scope.length > OAUTH2_CONSTANTS.SCOPE_MAX_LENGTH
    ) {
      throw new BadRequestException('scope parameter is too long');
    }

    const client = await this.validateClient(client_id, client_secret);

    // Validate scopes
    const scopeValue = typeof scope === 'string' ? scope : '';
    const requestedScopes = scopeValue ? scopeValue.split(' ') : [];
    const validScopes = await this.scopeService.validateScopes(requestedScopes);

    if (!validScopes && requestedScopes.length > 0) {
      throw new BadRequestException('Invalid scope parameter');
    }

    // Validate client-specific scopes
    if (!this.validateClientScopes(client, requestedScopes)) {
      throw new BadRequestException(
        'Client is not authorized for requested scopes',
      );
    }

    // Create token for client credentials
    const tokenResponse = await this.tokenService.createToken(
      null,
      client,
      requestedScopes,
    );

    return {
      access_token: tokenResponse.accessToken,
      token_type: tokenResponse.tokenType,
      expires_in: tokenResponse.expiresIn,
      scope: requestedScopes.join(' '),
    };
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

  async getUserInfo(userId: string): Promise<User> {
    const user = await this.userRepository.findOne({
      where: { id: parseInt(userId) },
    });

    if (!user) {
      throw new BadRequestException('User not found');
    }

    return user;
  }

  private async validateClient(
    clientId: string,
    clientSecret?: string,
  ): Promise<Client> {
    const client = await this.clientRepository.findOne({
      where: { clientId, isActive: true },
    });

    if (!client) {
      throw new UnauthorizedException('Invalid client credentials');
    }

    // For confidential clients, validate client secret
    if (client.isConfidential && client.clientSecret) {
      if (!clientSecret || clientSecret !== client.clientSecret) {
        throw new UnauthorizedException('Invalid client credentials');
      }
    }

    return client;
  }

  private sanitizeRedirectUri(redirectUri: string): string | null {
    try {
      const url = new URL(redirectUri);

      // Only allow HTTP/HTTPS schemes
      if (!['http:', 'https:'].includes(url.protocol)) {
        return null;
      }

      // Prevent localhost/private IP redirects in production
      if (process.env.NODE_ENV === 'production') {
        const hostname = url.hostname.toLowerCase();
        if (
          hostname === 'localhost' ||
          hostname === '127.0.0.1' ||
          hostname.startsWith('192.168.') ||
          hostname.startsWith('10.') ||
          hostname.startsWith('172.')
        ) {
          return null;
        }
      }

      // Remove fragment (#) as it's not allowed in redirect URIs
      url.hash = '';

      return url.toString();
    } catch {
      return null;
    }
  }

  private isValidRedirectUri(
    redirectUri: string,
    registeredUris: string[],
  ): boolean {
    // Exact match first
    if (registeredUris.includes(redirectUri)) {
      return true;
    }

    try {
      const requestUrl = new URL(redirectUri);

      // Check for prefix matches (more secure than wildcards)
      for (const registeredUri of registeredUris) {
        try {
          const registeredUrl = new URL(registeredUri);

          // Same scheme, host, port
          if (
            requestUrl.protocol === registeredUrl.protocol &&
            requestUrl.hostname === registeredUrl.hostname &&
            requestUrl.port === registeredUrl.port
          ) {
            // Path should start with registered path
            if (requestUrl.pathname.startsWith(registeredUrl.pathname)) {
              // If registered URI has query params, request must match them
              if (registeredUrl.search) {
                const registeredParams = new URLSearchParams(
                  registeredUrl.search,
                );
                const requestParams = new URLSearchParams(requestUrl.search);

                let paramsMatch = true;
                for (const [key, value] of registeredParams) {
                  if (requestParams.get(key) !== value) {
                    paramsMatch = false;
                    break;
                  }
                }

                if (!paramsMatch) {
                  continue;
                }
              }

              return true;
            }
          }
        } catch {
          // Invalid registered URI, skip
          continue;
        }
      }
    } catch {
      // Invalid redirect URI
      return false;
    }

    return false;
  }

  private checkRateLimit(
    identifier: string,
    maxRequests: number = RATE_LIMIT_CONSTANTS.MAX_REQUESTS,
  ): boolean {
    const now = Date.now();
    const key = `ratelimit:${identifier}`;
    const record = this.rateLimitStore.get(key);

    if (!record || now > record.resetTime) {
      // First request or window expired
      this.rateLimitStore.set(key, {
        count: 1,
        resetTime: now + RATE_LIMIT_CONSTANTS.WINDOW_MS,
      });
      return true;
    }

    if (record.count >= maxRequests) {
      return false; // Rate limit exceeded
    }

    record.count++;
    this.rateLimitStore.set(key, record);
    return true;
  }

  private cleanupRateLimitStore(): void {
    const now = Date.now();
    for (const [key, record] of this.rateLimitStore.entries()) {
      if (now > record.resetTime) {
        this.rateLimitStore.delete(key);
      }
    }
  }

  async getTotalClientsCount(userId: number): Promise<number> {
    return await this.clientRepository.count({
      where: { isActive: true, userId },
    });
  }

  async getActiveTokensCount(userId: number): Promise<number> {
    return await this.tokenService.getActiveTokensCountForUser(userId);
  }

  private validateClientScopes(
    client: Client,
    requestedScopes: string[],
  ): boolean {
    // If client has no scope restrictions, allow all valid scopes
    if (!client.scopes || client.scopes.length === 0) {
      return true;
    }

    // Check if all requested scopes are allowed for this client
    return requestedScopes.every((scope) => client.scopes?.includes(scope));
  }
}
