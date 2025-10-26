import {
  Injectable,
  NotFoundException,
  ForbiddenException,
  BadRequestException,
  Logger,
  Inject,
  InternalServerErrorException,
} from '@nestjs/common';
import { InjectRepository, InjectDataSource } from '@nestjs/typeorm';
import { Repository, DataSource } from 'typeorm';
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
import { AuditLogService } from '../../common/audit-log.service';
import {
  AuditEventType,
  AuditSeverity,
  RESOURCE_TYPES,
} from '../../common/audit-log.entity';

@Injectable()
export class ClientAuthService {
  private readonly logger = new Logger(ClientAuthService.name);

  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
    @InjectRepository(Client)
    private clientRepository: Repository<Client>,
    @InjectDataSource()
    private dataSource: DataSource,
    private fileUploadService: FileUploadService,
    @Inject(CACHE_MANAGER)
    private cacheManager: Cache,
    private auditLogService: AuditLogService,
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

    // Check if user has permission to create clients
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

    const savedClient = await this.clientRepository.save(client);

    // Record audit log for client creation
    try {
      await this.auditLogService.create({
        eventType: AuditEventType.CLIENT_CREATED,
        severity: AuditSeverity.MEDIUM,
        description: `OAuth2 클라이언트 "${name}"가 생성되었습니다.`,
        userId,
        clientId: savedClient.id,
        resourceId: savedClient.id,
        resourceType: RESOURCE_TYPES.CLIENT,
        metadata: {
          clientName: name,
          clientId: savedClient.clientId,
          redirectUris: redirectUris.length,
          grants: grants.join(', '),
          scopes: clientScopes.join(', '),
          hasLogo: !!logoUri,
          hasTerms: !!termsOfServiceUri,
          hasPolicy: !!policyUri,
        },
      });
    } catch (error) {
      this.logger.warn(
        'Failed to create audit log for client creation:',
        error,
      );
    }

    return savedClient;
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

    const updatedClient = await this.clientRepository.save(client);

    // Record audit log for client secret reset
    try {
      await this.auditLogService.create({
        eventType: AuditEventType.CLIENT_UPDATED,
        severity: AuditSeverity.HIGH,
        description: `OAuth2 클라이언트 "${client.name}"의 시크릿이 재설정되었습니다.`,
        userId,
        clientId: id,
        resourceId: id,
        resourceType: RESOURCE_TYPES.CLIENT,
        metadata: {
          clientName: client.name,
          clientId: client.clientId,
          action: 'SECRET_RESET',
          previousSecretLast4: client.clientSecret?.slice(-4),
        },
      });
    } catch (error) {
      this.logger.warn(
        'Failed to create audit log for client secret reset:',
        error,
      );
    }

    return updatedClient;
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
    return this.dataSource.transaction(async (manager) => {
      const client = await manager.findOne(Client, {
        where: { id },
        relations: ['user'],
      });

      if (!client) {
        throw new NotFoundException('Client not found');
      }

      // Get requesting user information
      const requestUser = await manager.findOne(User, {
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

      // Count related tokens and authorization codes before deletion
      const tokenCount = await manager.count(Token, {
        where: { client: { id } },
      });

      const authCodeCount = await manager.count(AuthorizationCode, {
        where: { client: { id } },
      });

      this.logger.log(
        `Deleting client ${client.name} (ID: ${id}) with ${tokenCount} tokens and ${authCodeCount} authorization codes`,
      );

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

      try {
        // Delete the client
        await manager.remove(Client, client);

        // Log successful deletion
        this.logger.log(
          `Successfully deleted client ${client.name} (ID: ${id}) and ${tokenCount} related tokens and ${authCodeCount} authorization codes`,
        );

        // Record audit log for client deletion
        try {
          await this.auditLogService.create({
            eventType: AuditEventType.CLIENT_DELETED,
            severity: AuditSeverity.HIGH,
            description: `OAuth2 클라이언트 "${client.name}"가 삭제되었습니다. ${tokenCount}개의 토큰과 ${authCodeCount}개의 인증 코드가 함께 삭제되었습니다.`,
            userId: requestUserId,
            clientId: id,
            resourceId: id,
            resourceType: RESOURCE_TYPES.CLIENT,
            metadata: {
              clientName: client.name,
              clientId: client.clientId,
              deletedTokensCount: tokenCount,
              deletedAuthCodesCount: authCodeCount,
              requestedByUserId: requestUserId,
              isAdminDeletion: hasDeletePermission && !canDeleteOwnClient,
            },
          });
        } catch (error) {
          this.logger.warn(
            'Failed to create audit log for client deletion:',
            error,
          );
        }

        // Invalidate related caches
        try {
          // Clear general cache patterns for this client
          const clientCacheKeys = [
            `client:${id}`,
            `client:${id}:*`,
            `user:${client.userId}:clients`,
          ];

          for (const pattern of clientCacheKeys) {
            // Note: Basic cache manager doesn't support patterns, so we clear what we can
            await this.cacheManager.del(pattern);
          }
        } catch (error) {
          this.logger.warn(
            'Failed to invalidate caches after client deletion',
            error,
          );
        }
      } catch (error) {
        this.logger.error(`Failed to delete client ${id}:`, error);
        throw new InternalServerErrorException(
          'Failed to delete client due to database constraint or related data issues',
        );
      }
    });
  }
}
