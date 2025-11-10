import {
  Injectable,
  NotFoundException,
  ForbiddenException,
  BadRequestException,
  Logger,
} from '@nestjs/common';
import { InjectRepository, InjectDataSource } from '@nestjs/typeorm';
import { Repository, DataSource } from 'typeorm';
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
import { CacheManagerService } from '../../cache/cache-manager.service';
import { EmailService } from '../../email/email.service';

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
    private cacheManagerService: CacheManagerService,
    private auditLogService: AuditLogService,
    private emailService: EmailService,
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
    if (
      logoUri &&
      !validateWebUrl(logoUri) &&
      !logoUri.startsWith('/uploads/')
    ) {
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
    const clientId = (await snowflakeGenerator.generate()).toString();
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

    // Invalidate user cache since client list may be cached
    try {
      await this.cacheManagerService.invalidateUserOAuth2Cache(userId);
    } catch (error) {
      this.logger.warn(
        'Failed to invalidate user cache after client creation',
        error,
      );
    }

    // 클라이언트 생성 알림 이메일 전송 (큐 기반 비동기)
    try {
      await this.emailService.queueClientCreated(
        user.email,
        user.username,
        savedClient.name,
        savedClient.clientId,
      );
      this.logger.log(
        `Client created notification queued for ${user.email} (client: ${savedClient.name})`,
      );
    } catch (emailError) {
      this.logger.warn(
        `Failed to queue client created notification for ${user.email}: ${emailError instanceof Error ? emailError.message : 'Unknown error'}`,
      );
    }

    return savedClient;
  }

  async getClients(userId: number): Promise<Client[]> {
    const clients = await this.clientRepository.find({
      where: { userId },
      relations: ['user'],
    });

    // Log client logo URIs for debugging
    clients.forEach((client) => {
      if (client.logoUri) {
        this.logger.log(
          `Client ${client.name} (ID: ${client.id}) has logoUri: ${client.logoUri}`,
        );
      }
    });

    return clients;
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

    return await this.clientRepository.save(client);
  }

  async deleteClient(id: number, requestUserId: number): Promise<void> {
    // Validate permissions outside of transaction
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

    // Store data for audit log before deletion
    const auditData = {
      clientName: client.name,
      clientId: client.clientId,
      logoUri: client.logoUri,
    };

    // Execute deletion in a focused transaction
    let deletedTokensCount = 0;
    let deletedAuthCodesCount = 0;

    await this.dataSource.transaction(async (manager) => {
      // Count related tokens and authorization codes before deletion
      deletedTokensCount = await manager.count(Token, {
        where: { client: { id } },
      });

      deletedAuthCodesCount = await manager.count(AuthorizationCode, {
        where: { client: { id } },
      });

      this.logger.log(
        `Deleting client ${auditData.clientName} (ID: ${id}) with ${deletedTokensCount} tokens and ${deletedAuthCodesCount} authorization codes`,
      );

      // Delete the client (cascade will handle tokens and auth codes)
      await manager.remove(Client, client);

      this.logger.log(
        `Successfully deleted client ${auditData.clientName} (ID: ${id}) and ${deletedTokensCount} related tokens and ${deletedAuthCodesCount} authorization codes`,
      );
    });

    // Handle file deletion outside transaction
    if (auditData.logoUri) {
      try {
        this.fileUploadService.deleteFile(auditData.logoUri);
      } catch (error) {
        this.logger.warn(
          `Failed to delete logo file: ${auditData.logoUri}`,
          error,
        );
      }
    }

    // Invalidate related caches
    try {
      const clientCacheKeys = [
        `client:${id}`,
        `client:${id}:*`,
        `user:${client.userId}:clients`,
      ];

      for (const pattern of clientCacheKeys) {
        // Note: Basic cache manager doesn't support patterns, so we clear what we can
        await this.cacheManagerService.delCacheKey(pattern);
      }

      // Invalidate user cache since client list may be cached
      await this.cacheManagerService.invalidateUserOAuth2Cache(client.userId);
    } catch (error) {
      this.logger.warn(
        'Failed to invalidate caches after client deletion',
        error,
      );
    }

    // Record audit log outside transaction to avoid lock conflicts
    try {
      await this.auditLogService.create({
        eventType: AuditEventType.CLIENT_DELETED,
        severity: AuditSeverity.HIGH,
        description: `OAuth2 클라이언트 "${auditData.clientName}"가 삭제되었습니다. ${deletedTokensCount}개의 토큰과 ${deletedAuthCodesCount}개의 인증 코드가 함께 삭제되었습니다.`,
        userId: requestUserId,
        clientId: id,
        resourceId: id,
        resourceType: RESOURCE_TYPES.CLIENT,
        metadata: {
          clientName: auditData.clientName,
          clientId: auditData.clientId,
          deletedTokensCount: deletedTokensCount,
          deletedAuthCodesCount: deletedAuthCodesCount,
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
  }
}
