import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Scope } from '../oauth2/scope.entity';
import { Client } from '../oauth2/client.entity';
import { User } from '../auth/user.entity';
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
    {
      name: OAUTH2_SCOPES.OPENID,
      description: SCOPE_DESCRIPTIONS[OAUTH2_SCOPES.OPENID],
      isDefault: true,
    },
    {
      name: OAUTH2_SCOPES.PROFILE,
      description: SCOPE_DESCRIPTIONS[OAUTH2_SCOPES.PROFILE],
      isDefault: false,
    },
    {
      name: OAUTH2_SCOPES.EMAIL,
      description: SCOPE_DESCRIPTIONS[OAUTH2_SCOPES.EMAIL],
      isDefault: false,
    },
    {
      name: OAUTH2_SCOPES.IDENTIFY,
      description: SCOPE_DESCRIPTIONS[OAUTH2_SCOPES.IDENTIFY],
      isDefault: false,
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

  async seedScopes(): Promise<void> {
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
        scopes: [OAUTH2_SCOPES.IDENTIFY],
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
