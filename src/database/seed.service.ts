import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Scope } from '../scope/scope.entity';
import { Client } from '../client/client.entity';
import { User } from '../user/user.entity';
import { snowflakeGenerator } from '../utils/snowflake-id.util';
import {
  OAUTH2_SCOPES,
  SCOPE_DESCRIPTIONS,
} from '../constants/oauth2.constants';

interface ScopeData {
  readonly name: string;
  readonly description: string;
  readonly isDefault: boolean;
}

@Injectable()
export class SeedService {
  private readonly logger = new Logger(SeedService.name);

  private static readonly DEFAULT_SCOPES: readonly ScopeData[] = [
    // 기존 스코프들 (하위 호환성)
    {
      name: 'read',
      description: 'Read access to user data',
      isDefault: true,
    },
    {
      name: 'write',
      description: 'Write access to user data',
      isDefault: false,
    },
    {
      name: 'profile',
      description: 'Access to user profile information',
      isDefault: true,
    },
    {
      name: 'email',
      description: 'Access to user email',
      isDefault: true,
    },
    {
      name: 'openid',
      description: 'OpenID Connect identification',
      isDefault: true,
    },
    {
      name: 'offline_access',
      description: 'Offline access (refresh tokens)',
      isDefault: false,
    },
    // 새로운 OAuth2 스코프들
    {
      name: OAUTH2_SCOPES.READ_USER,
      description: SCOPE_DESCRIPTIONS[OAUTH2_SCOPES.READ_USER],
      isDefault: true,
    },
    {
      name: OAUTH2_SCOPES.WRITE_USER,
      description: SCOPE_DESCRIPTIONS[OAUTH2_SCOPES.WRITE_USER],
      isDefault: false,
    },
    {
      name: OAUTH2_SCOPES.DELETE_USER,
      description: SCOPE_DESCRIPTIONS[OAUTH2_SCOPES.DELETE_USER],
      isDefault: false,
    },
    {
      name: OAUTH2_SCOPES.READ_PROFILE,
      description: SCOPE_DESCRIPTIONS[OAUTH2_SCOPES.READ_PROFILE],
      isDefault: true,
    },
    {
      name: OAUTH2_SCOPES.WRITE_PROFILE,
      description: SCOPE_DESCRIPTIONS[OAUTH2_SCOPES.WRITE_PROFILE],
      isDefault: false,
    },
    {
      name: OAUTH2_SCOPES.UPLOAD_FILE,
      description: SCOPE_DESCRIPTIONS[OAUTH2_SCOPES.UPLOAD_FILE],
      isDefault: false,
    },
    {
      name: OAUTH2_SCOPES.READ_FILE,
      description: SCOPE_DESCRIPTIONS[OAUTH2_SCOPES.READ_FILE],
      isDefault: false,
    },
    {
      name: OAUTH2_SCOPES.DELETE_FILE,
      description: SCOPE_DESCRIPTIONS[OAUTH2_SCOPES.DELETE_FILE],
      isDefault: false,
    },
    {
      name: OAUTH2_SCOPES.READ_CLIENT,
      description: SCOPE_DESCRIPTIONS[OAUTH2_SCOPES.READ_CLIENT],
      isDefault: false,
    },
    {
      name: OAUTH2_SCOPES.WRITE_CLIENT,
      description: SCOPE_DESCRIPTIONS[OAUTH2_SCOPES.WRITE_CLIENT],
      isDefault: false,
    },
    {
      name: OAUTH2_SCOPES.DELETE_CLIENT,
      description: SCOPE_DESCRIPTIONS[OAUTH2_SCOPES.DELETE_CLIENT],
      isDefault: false,
    },
    {
      name: OAUTH2_SCOPES.ADMIN,
      description: SCOPE_DESCRIPTIONS[OAUTH2_SCOPES.ADMIN],
      isDefault: false,
    },
    {
      name: OAUTH2_SCOPES.BASIC,
      description: SCOPE_DESCRIPTIONS[OAUTH2_SCOPES.BASIC],
      isDefault: true,
    },
  ] as const;

  constructor(
    @InjectRepository(Scope)
    private readonly scopeRepository: Repository<Scope>,
    @InjectRepository(Client)
    private readonly clientRepository: Repository<Client>,
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
  ) {}

  async seedDatabase(): Promise<void> {
    this.logger.log('Starting database seeding...');

    await this.seedScopes();
    await this.seedDefaultClient();

    this.logger.log('Database seeding completed!');
  }

  private async seedScopes(): Promise<void> {
    this.logger.log('Seeding scopes...');

    for (const scopeData of SeedService.DEFAULT_SCOPES) {
      const existingScope = await this.scopeRepository.findOne({
        where: { name: scopeData.name },
      });

      if (!existingScope) {
        const scope = this.scopeRepository.create(scopeData);
        await this.scopeRepository.save(scope);
        this.logger.log(`Created scope: ${scopeData.name}`);
      } else {
        this.logger.log(`Scope already exists: ${scopeData.name}`);
      }
    }
  }

  private async seedDefaultClient(): Promise<void> {
    this.logger.log('Seeding default OAuth2 client...');

    const clientId = snowflakeGenerator.generate();
    const existingClient = await this.clientRepository.findOne({
      where: { name: 'Test Client' },
    });

    if (!existingClient) {
      // Find the first user to assign as the owner of the test client
      const firstUser = await this.userRepository
        .createQueryBuilder('user')
        .orderBy('user.id', 'ASC')
        .getOne();

      if (!firstUser) {
        this.logger.warn('No users found. Skipping default client creation.');
        return;
      }

      const client = this.clientRepository.create({
        name: 'Test Client',
        description: 'Default test client for OAuth2 development',
        clientId,
        clientSecret: 'test-client-secret',
        redirectUris: [
          'http://localhost:5173/callback',
          'http://localhost:3000/callback',
        ],
        grants: ['authorization_code', 'refresh_token'],
        scopes: ['read', 'write', 'profile', 'email'],
        isActive: true,
        userId: firstUser.id, // Assign to the first user
      });

      await this.clientRepository.save(client);
      this.logger.log(
        `Created default client with ID: ${clientId} assigned to user: ${firstUser.id}`,
      );
    } else {
      this.logger.log('Default client already exists');
    }
  }
}
