import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Scope } from '../scope/scope.entity';
import { Client } from '../client/client.entity';
import { snowflakeGenerator } from '../utils/snowflake-id.util';

interface ScopeData {
  readonly name: string;
  readonly description: string;
  readonly isDefault: boolean;
}

@Injectable()
export class SeedService {
  private static readonly DEFAULT_SCOPES: readonly ScopeData[] = [
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
  ] as const;

  constructor(
    @InjectRepository(Scope)
    private readonly scopeRepository: Repository<Scope>,
    @InjectRepository(Client)
    private readonly clientRepository: Repository<Client>,
  ) {}

  async seedDatabase(): Promise<void> {
    console.log('Starting database seeding...');

    await this.seedScopes();
    await this.seedDefaultClient();

    console.log('Database seeding completed!');
  }

  private async seedScopes(): Promise<void> {
    console.log('Seeding scopes...');

    for (const scopeData of SeedService.DEFAULT_SCOPES) {
      const existingScope = await this.scopeRepository.findOne({
        where: { name: scopeData.name },
      });

      if (!existingScope) {
        const scope = this.scopeRepository.create(scopeData);
        await this.scopeRepository.save(scope);
        console.log(`Created scope: ${scopeData.name}`);
      } else {
        console.log(`Scope already exists: ${scopeData.name}`);
      }
    }
  }

  private async seedDefaultClient(): Promise<void> {
    console.log('Seeding default OAuth2 client...');

    const clientId = snowflakeGenerator.generate();
    const existingClient = await this.clientRepository.findOne({
      where: { name: 'Test Client' },
    });

    if (!existingClient) {
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
      });

      await this.clientRepository.save(client);
      console.log(`Created default client with ID: ${clientId}`);
    } else {
      console.log('Default client already exists');
    }
  }
}
