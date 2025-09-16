import {
  Injectable,
  ConflictException,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { JwtService } from '@nestjs/jwt';
import { User } from '../user/user.entity';
import { Client } from '../client/client.entity';
import { Token } from '../token/token.entity';
import { AuthorizationCode } from '../authorization-code/authorization-code.entity';
import * as bcrypt from 'bcrypt';
import { CreateUserDto } from './dto/create-user.dto';
import { LoginDto } from './dto/login.dto';
import { CreateClientDto } from './dto/create-client.dto';
import {
  AUTH_CONSTANTS,
  AUTH_ERROR_MESSAGES,
  ROLES,
} from '../constants/auth.constants';
import { JwtPayload, LoginResponse } from '../types/auth.types';
import { snowflakeGenerator } from '../utils/snowflake-id.util';
import { CryptoUtils } from '../utils/crypto.util';
import { PermissionUtils } from '../utils/permission.util';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
    @InjectRepository(Client)
    private clientRepository: Repository<Client>,
    @InjectRepository(Token)
    private tokenRepository: Repository<Token>,
    @InjectRepository(AuthorizationCode)
    private authorizationCodeRepository: Repository<AuthorizationCode>,
    private jwtService: JwtService,
    private configService: ConfigService,
  ) {}

  async register(createUserDto: CreateUserDto): Promise<User> {
    const { username, email, password, firstName, lastName } = createUserDto;

    // Check if user already exists
    const existingUser = await this.userRepository.findOne({
      where: [{ username }, { email }],
    });

    if (existingUser) {
      throw new ConflictException(AUTH_ERROR_MESSAGES.USER_ALREADY_EXISTS);
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(
      password,
      AUTH_CONSTANTS.BCRYPT_SALT_ROUNDS,
    );

    // Check if this is the first user (should get admin permissions)
    const userCount = await this.userRepository.count();
    const isFirstUser = userCount === 0;

    // Create user
    const user = this.userRepository.create({
      username,
      email,
      password: hashedPassword,
      firstName,
      lastName,
      permissions: isFirstUser
        ? ROLES.ADMIN
        : AUTH_CONSTANTS.DEFAULT_USER_PERMISSIONS,
    });

    return this.userRepository.save(user);
  }

  async login(loginDto: LoginDto): Promise<LoginResponse> {
    const { email, password } = loginDto;

    try {
      // Find user
      const user = await this.userRepository.findOne({
        where: { email },
        select: [
          'id',
          'email',
          'username',
          'password',
          'firstName',
          'lastName',
          'permissions',
        ],
      });

      if (!user) {
        throw new UnauthorizedException(
          AUTH_ERROR_MESSAGES.INVALID_CREDENTIALS,
        );
      }

      // Check password
      const isPasswordValid = await bcrypt.compare(password, user.password);

      if (!isPasswordValid) {
        throw new UnauthorizedException(
          AUTH_ERROR_MESSAGES.INVALID_CREDENTIALS,
        );
      }

      // Generate JWT token with enhanced payload
      const payload: JwtPayload = {
        sub: user.id.toString(),
        email: user.email,
        username: user.username,
        roles: [PermissionUtils.getRoleName(user.permissions)], // 권한 기반 역할 계산
        type: AUTH_CONSTANTS.TOKEN_TYPE,
      };
      // Generate JWT token (uses global expiration settings)
      const accessToken = this.jwtService.sign(payload);

      return {
        user,
        accessToken,
        expiresIn: AUTH_CONSTANTS.TOKEN_EXPIRATION_SECONDS,
      };
    } catch (error) {
      if (error instanceof UnauthorizedException) {
        throw error;
      }

      throw new UnauthorizedException(AUTH_ERROR_MESSAGES.LOGIN_FAILED);
    }
  }

  async findById(id: number): Promise<User> {
    const user = await this.userRepository.findOne({ where: { id } });

    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    return user;
  }

  async createClient(createClientDto: CreateClientDto): Promise<Client> {
    const { name, description, redirectUris, grants } = createClientDto;

    // Generate clientId using Snowflake ID and clientSecret using crypto-safe random string
    const clientId = snowflakeGenerator.generate();
    const clientSecret = CryptoUtils.generateRandomString(64);

    const client = this.clientRepository.create({
      clientId,
      clientSecret,
      name,
      description,
      redirectUris,
      grants,
    });

    return this.clientRepository.save(client);
  }

  async getClients(): Promise<Client[]> {
    return this.clientRepository.find();
  }

  async getClientById(id: number): Promise<Client> {
    const client = await this.clientRepository.findOne({ where: { id } });

    if (!client) {
      throw new UnauthorizedException('Client not found');
    }

    return client;
  }

  async updateProfile(
    userId: number,
    updateData: Partial<User>,
  ): Promise<User> {
    const user = await this.userRepository.findOne({ where: { id: userId } });

    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    // 업데이트 가능한 필드만 허용
    const allowedFields = ['firstName', 'lastName'] as const;
    const filteredData: Partial<Pick<User, 'firstName' | 'lastName'>> = {};

    for (const field of allowedFields) {
      if (updateData[field] !== undefined) {
        filteredData[field] = updateData[field];
      }
    }

    await this.userRepository.update(userId, filteredData);

    const updatedUser = await this.userRepository.findOne({
      where: { id: userId },
    });
    if (!updatedUser) {
      throw new UnauthorizedException('User not found after update');
    }

    return updatedUser;
  }

  async updateClientStatus(id: number, isActive: boolean): Promise<Client> {
    const client = await this.clientRepository.findOne({ where: { id } });

    if (!client) {
      throw new UnauthorizedException('Client not found');
    }

    await this.clientRepository.update(id, { isActive });

    const updatedClient = await this.clientRepository.findOne({
      where: { id },
    });
    if (!updatedClient) {
      throw new UnauthorizedException('Client not found after update');
    }

    return updatedClient;
  }

  async updateClient(
    id: number,
    updateData: Partial<CreateClientDto>,
  ): Promise<Client> {
    const client = await this.clientRepository.findOne({ where: { id } });

    if (!client) {
      throw new UnauthorizedException('Client not found');
    }

    // Update only provided fields
    const updateFields: Partial<Client> = {};
    if (updateData.name !== undefined) updateFields.name = updateData.name;
    if (updateData.description !== undefined)
      updateFields.description = updateData.description;
    if (updateData.redirectUris !== undefined)
      updateFields.redirectUris = updateData.redirectUris;
    if (updateData.scopes !== undefined)
      updateFields.scopes = updateData.scopes;
    if (updateData.logoUri !== undefined)
      updateFields.logoUri = updateData.logoUri;
    if (updateData.termsOfServiceUri !== undefined)
      updateFields.termsOfServiceUri = updateData.termsOfServiceUri;
    if (updateData.policyUri !== undefined)
      updateFields.policyUri = updateData.policyUri;

    await this.clientRepository.update(id, updateFields);

    const updatedClient = await this.clientRepository.findOne({
      where: { id },
    });
    if (!updatedClient) {
      throw new UnauthorizedException('Client not found after update');
    }

    return updatedClient;
  }

  async deleteClient(id: number): Promise<void> {
    const client = await this.clientRepository.findOne({ where: { id } });

    if (!client) {
      throw new UnauthorizedException('Client not found');
    }

    // Delete related authorization codes
    await this.authorizationCodeRepository.delete({ client: { id } });

    // Delete related tokens
    await this.tokenRepository.delete({ client: { id } });

    // Delete the client
    await this.clientRepository.remove(client);
  }

  async getUserTokens(userId: number): Promise<Token[]> {
    return this.tokenRepository.find({
      where: { user: { id: userId } },
      relations: ['client'],
      order: { createdAt: 'DESC' },
    });
  }

  async revokeToken(userId: number, tokenId: number): Promise<void> {
    const token = await this.tokenRepository.findOne({
      where: { id: tokenId, user: { id: userId } },
    });

    if (!token) {
      throw new UnauthorizedException('Token not found');
    }

    token.isRevoked = true;
    await this.tokenRepository.save(token);
  }

  async revokeAllUserTokens(userId: number): Promise<void> {
    await this.tokenRepository.update(
      { user: { id: userId } },
      { isRevoked: true },
    );
  }
}
