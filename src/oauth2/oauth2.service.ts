import {
  Injectable,
  BadRequestException,
  UnauthorizedException,
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

@Injectable()
export class OAuth2Service {
  private static readonly SUPPORTED_RESPONSE_TYPE = 'code';
  private static readonly SUPPORTED_GRANT_TYPES = [
    'authorization_code',
    'refresh_token',
    'client_credentials',
  ] as const;

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
    user: User,
  ): Promise<{ client: Client; requestedScopes: string[] }> {
    const { client_id, redirect_uri, response_type, scope } = authorizeDto;

    // Type validation
    if (typeof client_id !== 'string') {
      throw new BadRequestException('Invalid client_id parameter');
    }
    if (typeof redirect_uri !== 'string') {
      throw new BadRequestException('Invalid redirect_uri parameter');
    }
    if (typeof response_type !== 'string') {
      throw new BadRequestException('Invalid response_type parameter');
    }

    // Validate response type
    if (response_type !== OAuth2Service.SUPPORTED_RESPONSE_TYPE) {
      throw new BadRequestException(
        `Unsupported response type: ${response_type}`,
      );
    }

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

    // Validate scopes
    const scopeValue = typeof scope === 'string' ? scope : '';
    const requestedScopes = scopeValue ? scopeValue.split(' ') : [];
    const validScopes = await this.scopeService.validateScopes(requestedScopes);

    if (!validScopes && requestedScopes.length > 0) {
      throw new BadRequestException('Invalid scope parameter');
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
    const {
      client_id,
      redirect_uri,
      response_type,
      scope,
      state,
      code_challenge,
      code_challenge_method,
    } = authorizeDto;

    // Type validation
    if (typeof client_id !== 'string') {
      throw new BadRequestException('Invalid client_id parameter');
    }
    if (typeof redirect_uri !== 'string') {
      throw new BadRequestException('Invalid redirect_uri parameter');
    }
    if (typeof response_type !== 'string') {
      throw new BadRequestException('Invalid response_type parameter');
    }

    // Validate response type
    if (response_type !== OAuth2Service.SUPPORTED_RESPONSE_TYPE) {
      throw new BadRequestException(
        `Unsupported response type: ${response_type}`,
      );
    }

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

    // Validate scopes
    const scopeValue = typeof scope === 'string' ? scope : '';
    const requestedScopes = scopeValue ? scopeValue.split(' ') : [];
    const validScopes = await this.scopeService.validateScopes(requestedScopes);

    if (!validScopes && requestedScopes.length > 0) {
      throw new BadRequestException('Invalid scope parameter');
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

  async token(tokenDto: TokenRequestDto): Promise<TokenResponseDto> {
    const { grant_type } = tokenDto;

    // Type validation
    if (typeof grant_type !== 'string') {
      throw new BadRequestException('Invalid grant_type parameter');
    }

    if (!OAuth2Service.SUPPORTED_GRANT_TYPES.includes(grant_type as never)) {
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
      scope: authCode.scopes.join(' '),
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

    await this.validateClient(client_id, client_secret);

    // Refresh token
    const tokenResponse = await this.tokenService.refreshToken(refresh_token);

    if (!tokenResponse) {
      throw new BadRequestException('Invalid refresh token');
    }

    return {
      access_token: tokenResponse.accessToken,
      token_type: tokenResponse.tokenType,
      expires_in: tokenResponse.expiresIn,
      refresh_token: tokenResponse.refreshToken,
      scope: tokenResponse.scopes.join(' '),
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

    const client = await this.validateClient(client_id, client_secret);

    // Validate scopes
    const scopeValue = typeof scope === 'string' ? scope : '';
    const requestedScopes = scopeValue ? scopeValue.split(' ') : [];
    const validScopes = await this.scopeService.validateScopes(requestedScopes);

    if (!validScopes && requestedScopes.length > 0) {
      throw new BadRequestException('Invalid scope parameter');
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

  async getUserInfo(userId: number): Promise<User> {
    const user = await this.userRepository.findOne({
      where: { id: userId },
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
}
