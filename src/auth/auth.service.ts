import { Injectable, UnauthorizedException, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { JwtService } from '@nestjs/jwt';
import { User } from './user.entity';
import { Client } from '../oauth2/client.entity';
import { Token } from '../oauth2/token.entity';
import { TokenDto } from './dto/response.dto';
import { CreateUserDto } from './dto/create-user.dto';
import { CreateClientDto } from './dto/create-client.dto';
import {
  AUTH_CONSTANTS,
  TOKEN_TYPES,
  type TokenType,
} from '../constants/auth.constants';
import { JwtPayload, LoginResponse } from '../types/auth.types';
import { PermissionUtils } from '../utils/permission.util';
import { UserAuthService } from './services/user-auth.service';
import { ClientAuthService } from './services/client-auth.service';
import { TwoFactorAuthService } from './services/two-factor-auth.service';
import { ValidationService } from './services/validation.service';
import type { AvailabilityResult } from '../constants/validation.constants';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
    @InjectRepository(Client)
    private clientRepository: Repository<Client>,
    @InjectRepository(Token)
    private tokenRepository: Repository<Token>,
    private jwtService: JwtService,
    private userAuthService: UserAuthService,
    private clientAuthService: ClientAuthService,
    private twoFactorAuthService: TwoFactorAuthService,
    private validationService: ValidationService,
  ) {}

  async register(createUserDto: CreateUserDto): Promise<User> {
    return this.userAuthService.register(createUserDto);
  }

  async checkEmailAvailability(email: string): Promise<AvailabilityResult> {
    return this.validationService.checkEmailAvailability(email);
  }

  async checkUsernameAvailability(
    username: string,
  ): Promise<AvailabilityResult> {
    return this.validationService.checkUsernameAvailability(username);
  }

  async login(
    loginDto: {
      email: string;
      password: string;
      recaptchaToken: string;
    },
    clientInfo?: {
      userAgent: string;
      ipAddress: string;
    },
  ): Promise<LoginResponse> {
    return this.userAuthService.login(loginDto, clientInfo);
  }

  async verifyTwoFactorToken(
    email: string,
    token: string,
  ): Promise<LoginResponse> {
    return this.twoFactorAuthService.verifyTwoFactorToken(email, token);
  }

  async verifyBackupCode(
    email: string,
    backupCode: string,
  ): Promise<LoginResponse> {
    return this.twoFactorAuthService.verifyBackupCode(email, backupCode);
  }

  async createClient(
    createClientDto: CreateClientDto,
    userId: number,
  ): Promise<Client> {
    return this.clientAuthService.createClient(createClientDto, userId);
  }

  async getClients(userId: number): Promise<Client[]> {
    return this.clientAuthService.getClients(userId);
  }

  async getClientById(id: number, userId: number): Promise<Client> {
    return this.clientAuthService.getClientById(id, userId);
  }

  async updateClientStatus(
    id: number,
    isActive: boolean,
    userId: number,
  ): Promise<Client> {
    const client = await this.clientRepository.findOne({
      where: { id, userId },
    });

    if (!client) {
      throw new UnauthorizedException('Client not found or access denied');
    }

    await this.clientRepository.update(id, { isActive });

    const updatedClient = await this.clientRepository.findOne({
      where: { id, userId },
    });
    if (!updatedClient) {
      throw new UnauthorizedException('Client not found after update');
    }

    return updatedClient;
  }

  async updateClient(
    id: number,
    updateData: Partial<CreateClientDto>,
    userId: number,
  ): Promise<Client> {
    const client = await this.clientRepository.findOne({
      where: { id, userId },
    });

    if (!client) {
      throw new UnauthorizedException('Client not found or access denied');
    }

    // Update only provided fields
    const updateFields: Partial<Client> = {};
    if (updateData.name !== undefined) updateFields.name = updateData.name;
    if (updateData.description !== undefined)
      updateFields.description = updateData.description || undefined;
    if (updateData.redirectUris !== undefined)
      updateFields.redirectUris = updateData.redirectUris;
    if (updateData.scopes !== undefined)
      updateFields.scopes = updateData.scopes;
    if (updateData.logoUri !== undefined)
      updateFields.logoUri = updateData.logoUri || undefined;
    if (updateData.termsOfServiceUri !== undefined)
      updateFields.termsOfServiceUri =
        updateData.termsOfServiceUri || undefined;
    if (updateData.policyUri !== undefined)
      updateFields.policyUri = updateData.policyUri || undefined;

    await this.clientRepository.update(id, updateFields);

    const updatedClient = await this.clientRepository.findOne({
      where: { id },
    });
    if (!updatedClient) {
      throw new UnauthorizedException('Client not found after update');
    }

    return updatedClient;
  }

  async resetClientSecret(id: number, userId: number): Promise<Client> {
    return this.clientAuthService.resetClientSecret(id, userId);
  }

  async removeClientLogo(id: number, userId: number): Promise<Client> {
    return this.clientAuthService.removeClientLogo(id, userId);
  }

  async deleteClient(id: number, userId: number): Promise<void> {
    return this.clientAuthService.deleteClient(id, userId);
  }

  async getUserTokens(userId: number): Promise<TokenDto[]> {
    const tokens = await this.tokenRepository.find({
      where: { user: { id: userId }, isRevoked: false },
      relations: ['client', 'user'],
      order: { createdAt: 'DESC' },
    });

    return tokens.map((token) => ({
      id: token.id,
      tokenType: token.tokenType,
      expiresAt: token.expiresAt.toISOString(),
      refreshExpiresAt: token.refreshExpiresAt?.toISOString(),
      scopes: token.scopes,
      userId: token.user!.id,
      clientId: token.client?.id,
      client: token.client
        ? {
            name: token.client.name,
            clientId: token.client.clientId,
          }
        : undefined,
      createdAt: token.createdAt.toISOString(),
      updatedAt: token.createdAt.toISOString(), // Use createdAt since updatedAt doesn't exist
    }));
  }

  async revokeToken(userId: number, tokenId: number): Promise<void> {
    const token = await this.tokenRepository.findOne({
      where: { id: tokenId, user: { id: userId } },
    });

    if (!token) {
      throw new UnauthorizedException('Token not found');
    }

    // Completely delete token to ensure session expiration
    await this.tokenRepository.delete({ id: tokenId });
  }

  async revokeAllUserTokens(userId: number): Promise<void> {
    await this.tokenRepository.delete({ user: { id: userId } });
  }

  async revokeAllTokensForType(
    userId: number,
    tokenType: TokenType,
  ): Promise<void> {
    await this.tokenRepository.delete({ user: { id: userId }, tokenType });
  }

  // JWT token refresh (for general login)
  async refreshToken(token: string): Promise<LoginResponse> {
    try {
      // Validate token
      const payload = this.jwtService.verify<JwtPayload>(token);

      // Find user
      const user = await this.userRepository.findOne({
        where: { id: parseInt(payload.sub, 10) },
        select: [
          'id',
          'email',
          'username',
          'firstName',
          'lastName',
          'permissions',
          'userType',
        ],
      });

      if (!user) {
        throw new UnauthorizedException('User not found');
      }

      // Generate new token (same method as before)
      const newPayload: JwtPayload = {
        sub: user.id.toString(),
        email: user.email,
        username: user.username,
        roles: [PermissionUtils.getRoleName(user.permissions)],
        permissions: user.permissions,
        type: TOKEN_TYPES.LOGIN,
      };

      const accessToken = this.jwtService.sign(newPayload);

      return {
        user,
        accessToken,
        expiresIn: AUTH_CONSTANTS.TOKEN_EXPIRATION_SECONDS,
      };
    } catch (error) {
      this.logger.error('Token refresh error:', error);
      throw new UnauthorizedException('Invalid or expired token');
    }
  }

  // Logout
  logout(token: string): { message: string } {
    try {
      // Validate token (optional: add to blacklist or perform other cleanup)
      this.jwtService.verify(token);

      return { message: 'Logged out successfully' };
    } catch (error) {
      this.logger.error('Logout error:', error);
      throw new UnauthorizedException('Invalid token');
    }
  }
}
