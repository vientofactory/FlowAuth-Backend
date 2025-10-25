import {
  Injectable,
  NotFoundException,
  ForbiddenException,
  BadRequestException,
  Logger,
  Inject,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import type { Cache } from 'cache-manager';
import { User } from '../user.entity';
import { Client } from '../../oauth2/client.entity';
import { Token } from '../../oauth2/token.entity';
import { AuthorizationCode } from '../../oauth2/authorization-code.entity';
import { CreateClientDto } from '../dto/create-client.dto';
import * as crypto from 'crypto';
import { snowflakeGenerator } from '../../utils/snowflake-id.util';
import { PermissionUtils } from '../../utils/permission.util';
import { PERMISSIONS } from '@flowauth/shared';
import {
  validateOAuth2RedirectUri,
  validateWebUrl,
} from '../../utils/url-security.util';
import { FileUploadService } from '../../upload/file-upload.service';

@Injectable()
export class ClientAuthService {
  private readonly logger = new Logger(ClientAuthService.name);

  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
    @InjectRepository(Client)
    private clientRepository: Repository<Client>,
    @InjectRepository(Token)
    private tokenRepository: Repository<Token>,
    @InjectRepository(AuthorizationCode)
    private authorizationCodeRepository: Repository<AuthorizationCode>,
    private fileUploadService: FileUploadService,
    @Inject(CACHE_MANAGER)
    private cacheManager: Cache,
  ) {}

  async createClient(
    createClientDto: CreateClientDto,
    userId: number,
  ): Promise<Client> {
    const user = await this.userRepository.findOne({
      where: { id: userId },
      select: ['id', 'permissions', 'userType', 'email', 'username'],
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    // Check if user has permission to create clients (ADMIN 우회 포함)
    if (
      !PermissionUtils.isAdmin(user.permissions) &&
      !PermissionUtils.hasPermission(user.permissions, PERMISSIONS.WRITE_CLIENT)
    ) {
      throw new ForbiddenException('Insufficient permissions');
    }

    const {
      name,
      description,
      redirectUris,
      grants,
      scopes,
      logoUri,
      termsOfServiceUri,
      policyUri,
    } = createClientDto;

    // Validate redirect URIs
    for (const uri of redirectUris) {
      if (!validateOAuth2RedirectUri(uri)) {
        throw new BadRequestException(`Invalid redirect URI: ${uri}`);
      }
    }

    // Validate optional web URIs
    if (logoUri && !validateWebUrl(logoUri)) {
      throw new BadRequestException(`Invalid logo URI: ${logoUri}`);
    }

    if (termsOfServiceUri && !validateWebUrl(termsOfServiceUri)) {
      throw new BadRequestException(
        `Invalid terms of service URI: ${termsOfServiceUri}`,
      );
    }

    if (policyUri && !validateWebUrl(policyUri)) {
      throw new BadRequestException(`Invalid policy URI: ${policyUri}`);
    }

    // Generate clientId using Snowflake ID and clientSecret using crypto-safe random string
    const clientId = snowflakeGenerator.generate().toString();
    const clientSecret = crypto.randomBytes(32).toString('hex');

    // Set default scopes if not provided
    const clientScopes = scopes && scopes.length > 0 ? scopes : ['identify'];

    // Create client
    const client = this.clientRepository.create({
      clientId,
      clientSecret,
      name,
      description,
      redirectUris,
      grants,
      scopes: clientScopes,
      logoUri,
      termsOfServiceUri,
      policyUri,
      userId,
      user,
    });

    return this.clientRepository.save(client);
  }

  async getClients(userId: number): Promise<Client[]> {
    return this.clientRepository.find({
      where: { userId },
      relations: ['user'],
    });
  }

  async getClientById(id: number, userId: number): Promise<Client> {
    const client = await this.clientRepository.findOne({
      where: { id, userId },
      relations: ['user'],
    });

    if (!client) {
      throw new NotFoundException('Client not found or access denied');
    }

    return client;
  }

  async resetClientSecret(id: number, userId: number): Promise<Client> {
    const client = await this.clientRepository.findOne({
      where: { id, userId },
    });

    if (!client) {
      throw new NotFoundException('Client not found or access denied');
    }

    // Generate new client secret
    const newClientSecret = crypto.randomBytes(32).toString('hex');

    // Update client
    client.clientSecret = newClientSecret;
    client.updatedAt = new Date();

    return this.clientRepository.save(client);
  }

  async removeClientLogo(id: number, userId: number): Promise<Client> {
    const client = await this.clientRepository.findOne({
      where: { id, userId },
    });

    if (!client) {
      throw new NotFoundException('Client not found or access denied');
    }

    // Remove logo file if exists
    if (client.logoUri) {
      try {
        this.fileUploadService.deleteFile(client.logoUri);
      } catch (error) {
        this.logger.warn(
          `Failed to delete logo file: ${client.logoUri}`,
          error,
        );
      }
    }

    // Update client
    client.logoUri = undefined;
    client.updatedAt = new Date();

    return this.clientRepository.save(client);
  }

  async deleteClient(id: number, requestUserId: number): Promise<void> {
    const client = await this.clientRepository.findOne({
      where: { id },
      relations: ['user'],
    });

    if (!client) {
      throw new NotFoundException('Client not found');
    }

    // Get requesting user information
    const requestUser = await this.userRepository.findOne({
      where: { id: requestUserId },
      select: ['id', 'permissions'],
    });

    if (!requestUser) {
      throw new NotFoundException('User not found');
    }

    // Permission validation: ADMIN or DELETE_CLIENT permission allows deleting any client
    const hasDeletePermission =
      PermissionUtils.isAdmin(requestUser.permissions) ||
      PermissionUtils.hasPermission(
        requestUser.permissions,
        PERMISSIONS.DELETE_CLIENT,
      );

    // Can also delete own client if has WRITE_CLIENT permission
    const canDeleteOwnClient =
      client.userId === requestUserId &&
      PermissionUtils.hasPermission(
        requestUser.permissions,
        PERMISSIONS.WRITE_CLIENT,
      );

    if (!hasDeletePermission && !canDeleteOwnClient) {
      throw new ForbiddenException(
        client.userId === requestUserId
          ? 'Insufficient permissions to delete your own client'
          : "Cannot delete other users' clients",
      );
    }

    // Remove logo file if exists
    if (client.logoUri) {
      try {
        this.fileUploadService.deleteFile(client.logoUri);
      } catch (error) {
        this.logger.warn(
          `Failed to delete logo file: ${client.logoUri}`,
          error,
        );
      }
    }

    // Delete the client (related tokens and authorization codes will be deleted automatically due to CASCADE DELETE)
    await this.clientRepository.remove(client);
  }
}
