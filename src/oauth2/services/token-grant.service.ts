import { Injectable, BadRequestException, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from '../../auth/user.entity';
import { Client } from '../client.entity';
import { AuthorizationCodeService } from '../authorization-code.service';
import { TokenService } from '../token.service';
import { ScopeService } from '../scope.service';
import { TokenRequestDto, TokenResponseDto } from '../dto/oauth2.dto';
import {
  OAUTH2_CONSTANTS,
  RATE_LIMIT_CONSTANTS,
  OAUTH2_ERROR_MESSAGES,
} from '../../constants/oauth2.constants';

@Injectable()
export class TokenGrantService {
  private readonly logger = new Logger(TokenGrantService.name);

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

  private checkRateLimit(
    key: string,
    maxRequests: number = RATE_LIMIT_CONSTANTS.MAX_REQUESTS,
  ): boolean {
    const now = Date.now();
    const windowMs = RATE_LIMIT_CONSTANTS.WINDOW_MS;

    const record = this.rateLimitStore.get(key);
    if (!record || now > record.resetTime) {
      // First request or window expired
      this.rateLimitStore.set(key, {
        count: 1,
        resetTime: now + windowMs,
      });
      return true;
    }

    if (record.count >= maxRequests) {
      return false;
    }

    record.count++;
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
    const { code, client_id, client_secret, redirect_uri, code_verifier } =
      tokenDto;

    // Type and length validation for parameters
    if (typeof code !== 'string') {
      throw new BadRequestException('Invalid code parameter');
    }
    if (code.length > OAUTH2_CONSTANTS.AUTHORIZATION_CODE_MAX_LENGTH) {
      throw new BadRequestException('code parameter is too long');
    }
    if (typeof client_id !== 'string') {
      throw new BadRequestException('Invalid client_id parameter');
    }
    if (client_id.length > OAUTH2_CONSTANTS.CLIENT_ID_MAX_LENGTH) {
      throw new BadRequestException('client_id parameter is too long');
    }
    if (client_secret && typeof client_secret !== 'string') {
      throw new BadRequestException('Invalid client_secret parameter');
    }
    if (redirect_uri && typeof redirect_uri !== 'string') {
      throw new BadRequestException('Invalid redirect_uri parameter');
    }
    if (
      redirect_uri &&
      redirect_uri.length > OAUTH2_CONSTANTS.REDIRECT_URI_MAX_LENGTH
    ) {
      throw new BadRequestException('redirect_uri parameter is too long');
    }
    if (code_verifier && typeof code_verifier !== 'string') {
      throw new BadRequestException('Invalid code_verifier parameter');
    }
    if (
      code_verifier &&
      code_verifier.length > OAUTH2_CONSTANTS.CODE_VERIFIER_MAX_LENGTH
    ) {
      throw new BadRequestException('code_verifier parameter is too long');
    }

    // Validate required parameters
    if (!code || !client_id) {
      throw new BadRequestException('Missing required parameters');
    }

    // Validate client
    const client = await this.validateClient(client_id, client_secret);

    // Validate and consume authorization code
    const authCode = await this.authCodeService.validateAndConsumeCode(
      code,
      client_id,
      redirect_uri,
      code_verifier,
    );

    // Generate tokens using the unified createToken method
    const tokenResult = await this.tokenService.createToken(
      authCode.user,
      client,
      authCode.scopes || [],
    );

    this.logger.log(
      `Tokens issued for user ${authCode.user.id} with scopes: ${(authCode.scopes || []).join(', ')}`,
    );

    return {
      access_token: tokenResult.accessToken,
      token_type: tokenResult.tokenType,
      expires_in: tokenResult.expiresIn,
      refresh_token: tokenResult.refreshToken,
      scope: (authCode.scopes || []).join(' '),
    };
  }

  private async handleRefreshTokenGrant(
    tokenDto: TokenRequestDto,
  ): Promise<TokenResponseDto> {
    const { refresh_token, client_id, client_secret, scope } = tokenDto;

    // Type validation
    if (typeof refresh_token !== 'string') {
      throw new BadRequestException('Invalid refresh_token parameter');
    }
    if (client_id && typeof client_id !== 'string') {
      throw new BadRequestException('Invalid client_id parameter');
    }
    if (client_secret && typeof client_secret !== 'string') {
      throw new BadRequestException('Invalid client_secret parameter');
    }
    if (scope && typeof scope !== 'string') {
      throw new BadRequestException('Invalid scope parameter');
    }

    // Validate required parameters
    if (!refresh_token) {
      throw new BadRequestException('Missing refresh_token parameter');
    }

    // Validate client if provided
    if (client_id) {
      await this.validateClient(client_id, client_secret);
    }

    // Use the existing refreshToken method from TokenService
    const tokenResult = await this.tokenService.refreshToken(
      refresh_token,
      client_id || '',
    );

    if (!tokenResult) {
      throw new BadRequestException('Invalid refresh token');
    }

    this.logger.log(
      `Tokens refreshed for user with scopes: ${tokenResult.scopes.join(', ')}`,
    );

    return {
      access_token: tokenResult.accessToken,
      token_type: tokenResult.tokenType,
      expires_in: tokenResult.expiresIn,
      refresh_token: tokenResult.refreshToken,
      scope: tokenResult.scopes.join(' '),
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
    if (client_secret && typeof client_secret !== 'string') {
      throw new BadRequestException('Invalid client_secret parameter');
    }
    if (scope && typeof scope !== 'string') {
      throw new BadRequestException('Invalid scope parameter');
    }

    // Validate required parameters
    if (!client_id || !client_secret) {
      throw new BadRequestException('Missing required parameters');
    }

    // Validate client
    const client = await this.validateClient(client_id, client_secret);

    // Parse requested scopes
    const requestedScopes = scope
      ? scope.split(' ').filter((s) => s.trim().length > 0)
      : [];

    // For client credentials, create tokens without a user (client-only access)
    const tokenResult = await this.tokenService.createToken(
      null, // No user for client credentials
      client,
      requestedScopes,
    );

    this.logger.log(
      `Client credentials token issued for client ${client.id} with scopes: ${requestedScopes.join(', ')}`,
    );

    return {
      access_token: tokenResult.accessToken,
      token_type: tokenResult.tokenType,
      expires_in: tokenResult.expiresIn,
      scope: requestedScopes.join(' '),
    };
  }

  private async validateClient(
    clientId: string,
    clientSecret?: string,
  ): Promise<Client> {
    const client = await this.clientRepository.findOne({
      where: { clientId, isActive: true },
    });

    if (!client) {
      throw new BadRequestException('Invalid client');
    }

    // Validate client secret if provided
    if (clientSecret && client.clientSecret !== clientSecret) {
      throw new BadRequestException('Invalid client credentials');
    }

    return client;
  }
}
