import {
  Injectable,
  ConflictException,
  UnauthorizedException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { JwtService } from '@nestjs/jwt';
import { User } from '../user/user.entity';
import { Client } from '../client/client.entity';
import * as bcrypt from 'bcrypt';
import { CreateUserDto } from './dto/create-user.dto';
import { LoginDto } from './dto/login.dto';
import { CreateClientDto } from './dto/create-client.dto';
import {
  AUTH_CONSTANTS,
  AUTH_ERROR_MESSAGES,
} from '../constants/auth.constants';
import { JwtPayload, LoginResponse } from '../types/auth.types';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
    @InjectRepository(Client)
    private clientRepository: Repository<Client>,
    private jwtService: JwtService,
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

    // Create user
    const user = this.userRepository.create({
      username,
      email,
      password: hashedPassword,
      firstName,
      lastName,
      roles: [...AUTH_CONSTANTS.DEFAULT_USER_ROLES], // Default role
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
          'roles',
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
        sub: user.id,
        email: user.email,
        username: user.username,
        roles: user.roles || [],
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

    // Generate clientId and clientSecret
    const clientId = this.generateRandomString(32);
    const clientSecret = this.generateRandomString(64);

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

  private generateRandomString(length: number): string {
    const chars =
      'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
      result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
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

  async deleteClient(id: number): Promise<void> {
    const client = await this.clientRepository.findOne({ where: { id } });

    if (!client) {
      throw new UnauthorizedException('Client not found');
    }

    await this.clientRepository.remove(client);
  }
}
