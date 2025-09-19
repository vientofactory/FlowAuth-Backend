import {
  Injectable,
  ConflictException,
  UnauthorizedException,
  Logger,
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
import * as speakeasy from 'speakeasy';
import { CreateUserDto } from './dto/create-user.dto';
import { CreateClientDto } from './dto/create-client.dto';
import {
  AUTH_CONSTANTS,
  AUTH_ERROR_MESSAGES,
  ROLES,
  USER_TYPES,
  USER_TYPE_PERMISSIONS,
} from '../constants/auth.constants';
import { JwtPayload, LoginResponse } from '../types/auth.types';
import { snowflakeGenerator } from '../utils/snowflake-id.util';
import { CryptoUtils } from '../utils/crypto.util';
import { PermissionUtils } from '../utils/permission.util';
import { TwoFactorService } from './two-factor.service';
import { FileUploadService } from '../upload/file-upload.service';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

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
    private fileUploadService: FileUploadService,
    private twoFactorService: TwoFactorService,
  ) {}

  async register(createUserDto: CreateUserDto): Promise<User> {
    const { username, email, password, firstName, lastName, userType } =
      createUserDto;

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

    // Determine user type and permissions
    const finalUserType = userType || USER_TYPES.REGULAR;
    let permissions: number;

    if (isFirstUser) {
      // First user is always admin
      permissions = ROLES.ADMIN;
    } else {
      // Set permissions based on user type
      permissions = USER_TYPE_PERMISSIONS[finalUserType];
    }

    // Create user
    const user = this.userRepository.create({
      username,
      email,
      password: hashedPassword,
      firstName,
      lastName,
      userType: finalUserType,
      permissions,
    });

    return this.userRepository.save(user);
  }

  async login(loginDto: {
    email: string;
    password: string;
  }): Promise<LoginResponse> {
    const { email, password } = loginDto;

    try {
      // Find user with 2FA fields
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
          'userType',
          'isTwoFactorEnabled',
          'twoFactorSecret',
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

      // Check if 2FA is enabled
      if (user.isTwoFactorEnabled) {
        // Return special response indicating 2FA is required
        throw new UnauthorizedException('2FA_REQUIRED');
      }

      // Update last login time
      await this.userRepository.update(user.id, {
        lastLoginAt: new Date(),
      });

      // Generate JWT token with enhanced payload
      const payload: JwtPayload = {
        sub: user.id.toString(),
        email: user.email,
        username: user.username,
        roles: [PermissionUtils.getRoleName(user.permissions)],
        permissions: user.permissions,
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

  async verifyTwoFactorToken(
    email: string,
    token: string,
  ): Promise<LoginResponse> {
    try {
      // Find user with 2FA fields
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
          'userType',
          'isTwoFactorEnabled',
          'twoFactorSecret',
        ],
      });

      if (!user) {
        throw new UnauthorizedException(
          AUTH_ERROR_MESSAGES.INVALID_CREDENTIALS,
        );
      }

      if (!user.isTwoFactorEnabled || !user.twoFactorSecret) {
        throw new UnauthorizedException(
          AUTH_ERROR_MESSAGES.TWO_FACTOR_NOT_ENABLED,
        );
      }

      // Verify 2FA token
      const isValidToken: boolean = (speakeasy as any).totp.verify({
        secret: user.twoFactorSecret,
        encoding: 'base32',
        token: token,
        window: 2, // Allow 2 time windows (30 seconds each)
      });

      if (!isValidToken) {
        throw new UnauthorizedException(
          AUTH_ERROR_MESSAGES.INVALID_TWO_FACTOR_TOKEN,
        );
      }

      // Update last login time
      await this.userRepository.update(user.id, {
        lastLoginAt: new Date(),
      });

      // Generate JWT token with enhanced payload
      const payload: JwtPayload = {
        sub: user.id.toString(),
        email: user.email,
        username: user.username,
        roles: [PermissionUtils.getRoleName(user.permissions)],
        permissions: user.permissions,
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

  async verifyBackupCode(
    email: string,
    backupCode: string,
  ): Promise<LoginResponse> {
    try {
      // Find user with 2FA fields
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
          'isTwoFactorEnabled',
          'twoFactorSecret',
          'backupCodes',
        ],
      });

      if (!user) {
        throw new UnauthorizedException(
          AUTH_ERROR_MESSAGES.INVALID_CREDENTIALS,
        );
      }

      if (!user.isTwoFactorEnabled || !user.backupCodes) {
        throw new UnauthorizedException(
          AUTH_ERROR_MESSAGES.TWO_FACTOR_NOT_ENABLED,
        );
      }

      // 백업 코드 검증 (two-factor.service 사용)
      const isValidBackupCode = await this.twoFactorService.verifyBackupCode(
        user.id,
        backupCode,
      );

      if (!isValidBackupCode) {
        throw new UnauthorizedException(
          AUTH_ERROR_MESSAGES.INVALID_BACKUP_CODE,
        );
      }

      // 백업 코드 검증 성공 - 사용자 정보 다시 가져오기
      const updatedUser = await this.userRepository.findOne({
        where: { id: user.id },
        select: [
          'id',
          'email',
          'username',
          'password',
          'firstName',
          'lastName',
          'permissions',
          'isTwoFactorEnabled',
          'twoFactorSecret',
          'backupCodes',
        ],
      });

      if (!updatedUser) {
        throw new UnauthorizedException(
          AUTH_ERROR_MESSAGES.INVALID_CREDENTIALS,
        );
      }

      // 사용자 정보 업데이트 (마지막 로그인 시간)
      await this.userRepository.update(user.id, {
        lastLoginAt: new Date(),
      });

      // Generate JWT token with enhanced payload
      const payload: JwtPayload = {
        sub: updatedUser.id.toString(),
        email: updatedUser.email,
        username: updatedUser.username,
        roles: [PermissionUtils.getRoleName(updatedUser.permissions)],
        permissions: updatedUser.permissions,
        type: AUTH_CONSTANTS.TOKEN_TYPE,
      };
      // Generate JWT token (uses global expiration settings)
      const accessToken = this.jwtService.sign(payload);

      return {
        user: updatedUser,
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

  async createClient(
    createClientDto: CreateClientDto,
    userId: number,
  ): Promise<Client> {
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
      scopes,
      logoUri,
      termsOfServiceUri,
      policyUri,
      userId,
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
      throw new UnauthorizedException('Client not found or access denied');
    }

    return client;
  }

  async updateClientStatus(
    id: number,
    isActive: boolean,
    userId: number,
  ): Promise<Client> {
    const client = await this.clientRepository.findOne({
      where: { id, userId },
    });

    if (!client) {
      throw new UnauthorizedException('Client not found or access denied');
    }

    await this.clientRepository.update(id, { isActive });

    const updatedClient = await this.clientRepository.findOne({
      where: { id, userId },
    });
    if (!updatedClient) {
      throw new UnauthorizedException('Client not found after update');
    }

    return updatedClient;
  }

  async updateClient(
    id: number,
    updateData: Partial<CreateClientDto>,
    userId: number,
  ): Promise<Client> {
    const client = await this.clientRepository.findOne({
      where: { id, userId },
    });

    if (!client) {
      throw new UnauthorizedException('Client not found or access denied');
    }

    // Update only provided fields
    const updateFields: Partial<Client> = {};
    if (updateData.name !== undefined) updateFields.name = updateData.name;
    if (updateData.description !== undefined)
      updateFields.description = updateData.description || undefined;
    if (updateData.redirectUris !== undefined)
      updateFields.redirectUris = updateData.redirectUris;
    if (updateData.scopes !== undefined)
      updateFields.scopes = updateData.scopes;
    if (updateData.logoUri !== undefined)
      updateFields.logoUri = updateData.logoUri || undefined;
    if (updateData.termsOfServiceUri !== undefined)
      updateFields.termsOfServiceUri =
        updateData.termsOfServiceUri || undefined;
    if (updateData.policyUri !== undefined)
      updateFields.policyUri = updateData.policyUri || undefined;

    await this.clientRepository.update(id, updateFields);

    const updatedClient = await this.clientRepository.findOne({
      where: { id },
    });
    if (!updatedClient) {
      throw new UnauthorizedException('Client not found after update');
    }

    return updatedClient;
  }

  async resetClientSecret(id: number, userId: number): Promise<Client> {
    const client = await this.clientRepository.findOne({
      where: { id, userId },
    });

    if (!client) {
      throw new UnauthorizedException('Client not found or access denied');
    }

    // Generate new client secret
    const newClientSecret = CryptoUtils.generateRandomString(64);

    await this.clientRepository.update(id, { clientSecret: newClientSecret });

    const updatedClient = await this.clientRepository.findOne({
      where: { id, userId },
    });
    if (!updatedClient) {
      throw new UnauthorizedException('Client not found after update');
    }

    return updatedClient;
  }

  async removeClientLogo(id: number, userId: number): Promise<Client> {
    const client = await this.clientRepository.findOne({
      where: { id, userId },
    });

    if (!client) {
      throw new UnauthorizedException('Client not found or access denied');
    }

    // Delete logo file if exists
    if (client.logoUri) {
      try {
        const deleted = this.fileUploadService.deleteFile(client.logoUri);
        if (!deleted) {
          this.logger.warn(
            `Failed to delete logo file (file may not exist): ${client.logoUri}`,
          );
        }
      } catch (error) {
        this.logger.error(
          `Error deleting logo file: ${client.logoUri}`,
          error instanceof Error ? error.stack : String(error),
        );
        // Continue with logo URI removal even if file deletion fails
      }
    }

    // Remove logo URI from client
    await this.clientRepository.query(
      'UPDATE client SET logoUri = NULL WHERE id = ?',
      [id],
    );

    const updatedClient = await this.clientRepository.findOne({
      where: { id },
    });

    if (!updatedClient) {
      throw new UnauthorizedException('Client not found after logo removal');
    }

    return updatedClient;
  }

  async deleteClient(id: number): Promise<void> {
    const client = await this.clientRepository.findOne({ where: { id } });

    if (!client) {
      throw new UnauthorizedException('Client not found');
    }

    // Delete logo file if exists
    if (client.logoUri) {
      try {
        this.fileUploadService.deleteFile(client.logoUri);
      } catch (error) {
        this.logger.error(
          `Error deleting logo file: ${client.logoUri}`,
          error instanceof Error ? error.stack : String(error),
        );
        // Continue with client deletion even if file deletion fails
        this.logger.warn(
          'Continuing with client deletion despite logo file deletion failure',
        );
      }
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

  // 로그아웃
  logout(token: string): { message: string } {
    try {
      // 토큰 검증 (옵션: 블랙리스트에 추가하거나 다른 정리 작업 수행)
      this.jwtService.verify(token);

      return { message: 'Logged out successfully' };
    } catch (error) {
      this.logger.error('Logout error:', error);
      throw new UnauthorizedException('Invalid token');
    }
  }
}
