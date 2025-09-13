import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Scope } from '../scope/scope.entity';

@Injectable()
export class ScopeService {
  constructor(
    @InjectRepository(Scope)
    private readonly scopeRepository: Repository<Scope>,
  ) {}

  async createScope(
    name: string,
    description: string,
    isDefault = false,
  ): Promise<Scope> {
    const scope = this.scopeRepository.create({
      name,
      description,
      isDefault,
    });

    return this.scopeRepository.save(scope);
  }

  async findByNames(names: string[]): Promise<Scope[]> {
    if (names.length === 0) {
      return [];
    }

    return this.scopeRepository.find({
      where: names.map((name) => ({ name })),
    });
  }

  async findAll(): Promise<Scope[]> {
    return this.scopeRepository.find({
      where: { isActive: true },
      order: { name: 'ASC' },
    });
  }

  async findDefaultScopes(): Promise<Scope[]> {
    return this.scopeRepository.find({
      where: { isDefault: true, isActive: true },
      order: { name: 'ASC' },
    });
  }

  async validateScopes(scopeNames: string[]): Promise<boolean> {
    if (scopeNames.length === 0) {
      return true;
    }

    const validScopes = await this.findByNames(scopeNames);
    return validScopes.length === scopeNames.length;
  }
}
