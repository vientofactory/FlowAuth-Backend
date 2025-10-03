import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, LessThan } from 'typeorm';
import { BadRequestException } from '@nestjs/common';
import { AppConfigService } from '../config/app-config.service';
import { AuthorizationCode } from './authorization-code.entity';
import { User } from '../auth/user.entity';
import { Client } from './client.entity';
import {
  OAUTH2_ERROR_MESSAGES,
  OAUTH2_CONSTANTS,
} from '../constants/oauth2.constants';
import * as crypto from 'crypto';

@Injectable()
export class AuthorizationCodeService {
  constructor(
    @InjectRepository(AuthorizationCode)
    private readonly authCodeRepository: Repository<AuthorizationCode>,
    private readonly appConfig: AppConfigService,
  ) {}

  private getCodeExpiryMinutes(): number {
    return this.appConfig.codeExpiryMinutes;
  }

  async createAuthorizationCode(
    user: User,
    client: Client,
    redirectUri: string,
    scopes: string[] = [],
    state?: string,
    codeChallenge?: string,
    codeChallengeMethod?: string,
    nonce?: string,
  ): Promise<AuthorizationCode> {
    const code = this.generateCode();

    const expiresAt = new Date();
    expiresAt.setMinutes(expiresAt.getMinutes() + this.getCodeExpiryMinutes());

    const authCode = this.authCodeRepository.create({
      code,
      expiresAt,
      redirectUri,
      scopes,
      state,
      codeChallenge,
      codeChallengeMethod,
      nonce,
      authTime: Math.floor(Date.now() / 1000),
      user,
      client,
    });

    const savedAuthCode = await this.authCodeRepository.save(authCode);
    return savedAuthCode;
  }

  async validateAndConsumeCode(
    code: string,
    clientId: string,
    redirectUri?: string,
    codeVerifier?: string,
  ): Promise<AuthorizationCode> {
    const authCode = await this.findValidAuthorizationCode(code);

    if (!authCode) {
      throw new BadRequestException('Invalid authorization code');
    }

    if (authCode.client.clientId !== clientId) {
      throw new BadRequestException('Invalid client');
    }

    if (redirectUri && authCode.redirectUri !== redirectUri) {
      throw new BadRequestException('Invalid redirect URI');
    }

    // Validate PKCE if present
    if (authCode.codeChallenge) {
      if (!codeVerifier) {
        throw new BadRequestException('Code verifier required');
      }

      const isValidPKCE = this.verifyCodeChallenge(
        codeVerifier,
        authCode.codeChallenge,
        authCode.codeChallengeMethod,
      );

      if (!isValidPKCE) {
        throw new BadRequestException('Invalid code verifier');
      }
    }

    authCode.isUsed = true;
    await this.authCodeRepository.save(authCode);

    return authCode;
  }

  private async findValidAuthorizationCode(
    code: string,
  ): Promise<AuthorizationCode | null> {
    const authCode = await this.authCodeRepository.findOne({
      where: { code, isUsed: false },
      relations: ['user', 'client'],
    });

    if (!authCode) {
      return null;
    }

    // Check expiration
    if (authCode.expiresAt < new Date()) {
      return null;
    }

    return authCode;
  }

  private validateAuthorizationCode(
    authCode: AuthorizationCode,
    clientId: string,
    redirectUri?: string,
  ): void {
    // Check client
    if (authCode.client.clientId !== clientId) {
      throw new BadRequestException(
        OAUTH2_ERROR_MESSAGES.INVALID_CLIENT_CREDENTIALS,
      );
    }

    // Check redirect URI if provided
    if (redirectUri && authCode.redirectUri !== redirectUri) {
      throw new BadRequestException(
        OAUTH2_ERROR_MESSAGES.INVALID_REDIRECT_URI_CLIENT,
      );
    }
  }

  private validateAndProcessPKCE(
    authCode: AuthorizationCode,
    codeVerifier?: string,
  ): void {
    // Check PKCE if code challenge was used (PKCE is now optional)
    if (authCode.codeChallenge) {
      if (!codeVerifier) {
        throw new BadRequestException(
          OAUTH2_ERROR_MESSAGES.PKCE_VERIFIER_REQUIRED,
        );
      }

      // Use stored method or default to 'plain'
      const method = authCode.codeChallengeMethod || 'plain';

      this.verifyCodeChallenge(codeVerifier, authCode.codeChallenge, method);
    }
  }

  async cleanupExpiredCodes(): Promise<number> {
    const now = new Date();
    const result = await this.authCodeRepository.delete({
      expiresAt: LessThan(now),
    });
    return result.affected || 0;
  }

  private generateCode(): string {
    return crypto.randomBytes(this.appConfig.codeLength).toString('hex');
  }

  private verifyCodeChallenge(
    verifier: string,
    challenge: string,
    method: string = 'plain',
  ): boolean {
    this.validatePKCEParameters(verifier, challenge);

    // Validate challenge length based on method
    if (method === 'S256' && challenge.length !== 43) {
      throw new BadRequestException(
        'Invalid code_challenge length for S256 method. Must be exactly 43 characters.',
      );
    }

    if (method === 'plain') {
      return this.verifyPlainChallenge(verifier, challenge);
    } else if (method === 'S256') {
      return this.verifyS256Challenge(verifier, challenge);
    }

    throw new BadRequestException(
      `${OAUTH2_ERROR_MESSAGES.UNSUPPORTED_PKCE_METHOD}: ${method}. Supported methods are 'plain' and 'S256'`,
    );
  }

  private validatePKCEParameters(verifier: string, challenge: string): void {
    if (!verifier || !challenge) {
      throw new BadRequestException(OAUTH2_ERROR_MESSAGES.PKCE_PARAMS_MISSING);
    }

    // Validate verifier length (RFC 7636: 43-128 characters)
    if (verifier.length < 43 || verifier.length > 128) {
      throw new BadRequestException(
        'Invalid code_verifier length. Must be between 43 and 128 characters.',
      );
    }

    // Validate verifier format (RFC 7636: unreserved characters)
    if (!OAUTH2_CONSTANTS.PKCE_UNRESERVED_CHAR_PATTERN.test(verifier)) {
      throw new BadRequestException(
        'Invalid code_verifier format. Only unreserved characters are allowed.',
      );
    }

    // Validate challenge format
    if (!OAUTH2_CONSTANTS.PKCE_UNRESERVED_CHAR_PATTERN.test(challenge)) {
      throw new BadRequestException(
        'Invalid code_challenge format. Only unreserved characters are allowed.',
      );
    }
  }

  private verifyPlainChallenge(verifier: string, challenge: string): boolean {
    if (verifier !== challenge) {
      throw new BadRequestException(
        OAUTH2_ERROR_MESSAGES.PKCE_VERIFICATION_FAILED_PLAIN,
      );
    }
    return true;
  }

  private verifyS256Challenge(verifier: string, challenge: string): boolean {
    const hash = crypto
      .createHash('sha256')
      .update(verifier)
      .digest('base64url');

    if (hash !== challenge) {
      throw new BadRequestException(
        OAUTH2_ERROR_MESSAGES.PKCE_VERIFICATION_FAILED_S256,
      );
    }
    return true;
  }
}
