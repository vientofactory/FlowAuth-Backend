import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { AuthorizationCode } from '../authorization-code/authorization-code.entity';
import { User } from '../user/user.entity';
import { Client } from '../client/client.entity';
import * as crypto from 'crypto';

@Injectable()
export class AuthorizationCodeService {
  private static readonly CODE_EXPIRY_MINUTES = 10;
  private static readonly CODE_LENGTH = 32;

  constructor(
    @InjectRepository(AuthorizationCode)
    private readonly authCodeRepository: Repository<AuthorizationCode>,
  ) {}

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
    expiresAt.setMinutes(
      expiresAt.getMinutes() + AuthorizationCodeService.CODE_EXPIRY_MINUTES,
    );

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

    // Check client
    if (authCode.client.clientId !== clientId) {
      return null;
    }

    // Check redirect URI if provided
    if (redirectUri && authCode.redirectUri !== redirectUri) {
      return null;
    }

    // Check PKCE if code challenge was used
    if (authCode.codeChallenge && codeVerifier) {
      if (
        !this.verifyCodeChallenge(
          codeVerifier,
          authCode.codeChallenge,
          authCode.codeChallengeMethod,
        )
      ) {
        return null;
      }
    }

    // Mark as used
    authCode.isUsed = true;
    await this.authCodeRepository.save(authCode);

    return authCode;
  }

  private generateCode(): string {
    return crypto
      .randomBytes(AuthorizationCodeService.CODE_LENGTH)
      .toString('hex');
  }

  private verifyCodeChallenge(
    verifier: string,
    challenge: string,
    method: string = 'plain',
  ): boolean {
    if (method === 'plain') {
      return verifier === challenge;
    } else if (method === 'S256') {
      const hash = crypto
        .createHash('sha256')
        .update(verifier)
        .digest('base64url');
      return hash === challenge;
    }
    return false;
  }
}
