import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, LessThan } from 'typeorm';
import { BadRequestException } from '@nestjs/common';
import { AppConfigService } from '../config/app-config.service';
import { AuthorizationCode } from '../authorization-code/authorization-code.entity';
import { User } from '../user/user.entity';
import { Client } from '../client/client.entity';
import { OAUTH2_ERROR_MESSAGES } from '../constants/oauth2.constants';
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
      user,
      client,
    });

    return this.authCodeRepository.save(authCode);
  }

  async validateAndConsumeCode(
    code: string,
    clientId: string,
    redirectUri?: string,
    codeVerifier?: string,
  ): Promise<AuthorizationCode | null> {
    const authCode = await this.findValidAuthorizationCode(code);

    if (!authCode) {
      return null;
    }

    this.validateAuthorizationCode(authCode, clientId, redirectUri);
    this.validateAndProcessPKCE(authCode, codeVerifier);

    // Mark as used and delete immediately to prevent reuse
    authCode.isUsed = true;
    await this.authCodeRepository.save(authCode);

    // Immediately delete the authorization code to prevent any reuse attempts
    await this.authCodeRepository.remove(authCode);

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
      this.verifyCodeChallenge(
        codeVerifier,
        authCode.codeChallenge,
        authCode.codeChallengeMethod,
      );
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
