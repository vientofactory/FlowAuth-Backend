import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Scope } from '../scope/scope.entity';

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
  ) {}

  async seedDatabase(): Promise<void> {
    console.log('🌱 Starting database seeding...');

    await this.seedScopes();

    console.log('✅ Database seeding completed!');
  }

  private async seedScopes(): Promise<void> {
    console.log('📋 Seeding scopes...');

    for (const scopeData of SeedService.DEFAULT_SCOPES) {
      const existingScope = await this.scopeRepository.findOne({
        where: { name: scopeData.name },
      });

      if (!existingScope) {
        const scope = this.scopeRepository.create(scopeData);
        await this.scopeRepository.save(scope);
        console.log(`   ✅ Created scope: ${scopeData.name}`);
      } else {
        console.log(`   ⚠️  Scope already exists: ${scopeData.name}`);
      }
    }
  }
}
