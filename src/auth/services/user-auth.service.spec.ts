import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { UnauthorizedException } from '@nestjs/common';
import * as bcrypt from 'bcrypt';

import { UserAuthService } from './user-auth.service';
import { User } from '../user.entity';
import { Token } from '../../oauth2/token.entity';
import { RecaptchaService } from '../../utils/recaptcha.util';
import { CacheManagerService } from '../../cache/cache-manager.service';
import { AuditLogService } from '../../common/audit-log.service';

// Mock bcrypt
jest.mock('bcrypt');
const mockedBcrypt = bcrypt as jest.Mocked<typeof bcrypt>;

describe('UserAuthService', () => {
  let service: UserAuthService;
  let userRepository: jest.Mocked<Repository<User>>;
  let tokenRepository: jest.Mocked<Repository<Token>>;
  let jwtService: jest.Mocked<JwtService>;
  let recaptchaService: jest.Mocked<RecaptchaService>;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        UserAuthService,
        {
          provide: getRepositoryToken(User),
          useValue: {
            findOne: jest.fn(),
            save: jest.fn(),
            create: jest.fn(),
            update: jest.fn(),
          },
        },
        {
          provide: getRepositoryToken(Token),
          useValue: {
            findOne: jest.fn(),
            save: jest.fn(),
            create: jest.fn(),
          },
        },
        {
          provide: JwtService,
          useValue: {
            sign: jest.fn(),
          },
        },
        {
          provide: ConfigService,
          useValue: {
            get: jest.fn(),
          },
        },
        {
          provide: RecaptchaService,
          useValue: {
            verifyToken: jest.fn(),
          },
        },
        {
          provide: CacheManagerService,
          useValue: {
            delCacheKey: jest.fn(),
          },
        },
        {
          provide: AuditLogService,
          useValue: {
            create: jest.fn(),
          },
        },
      ],
    }).compile();

    service = module.get<UserAuthService>(UserAuthService);
    userRepository = module.get(getRepositoryToken(User));
    tokenRepository = module.get(getRepositoryToken(Token));
    jwtService = module.get(JwtService);
    recaptchaService = module.get(RecaptchaService);
  });

  describe('login', () => {
    const mockLoginDto = {
      email: 'test@example.com',
      password: 'password123',
      recaptchaToken: 'valid-recaptcha-token',
    };

    const mockUser = {
      id: 1,
      userId: 'user123',
      email: 'test@example.com',
      username: 'testuser',
      password: 'hashedPassword',
      firstName: 'Test',
      lastName: 'User',
      permissions: 1,
      userType: 'regular',
      isTwoFactorEnabled: false,
      twoFactorSecret: undefined,
      isEmailVerified: true,
      avatar: null,
      isActive: true,
      createdAt: new Date(),
      updatedAt: new Date(),
    } as User;

    beforeEach(() => {
      recaptchaService.verifyToken.mockResolvedValue(true);
      mockedBcrypt.compare.mockResolvedValue(true as never);
      jwtService.sign.mockReturnValue('jwt-token');
      const mockToken = { id: 1 } as Token;
      tokenRepository.create.mockReturnValue(mockToken);
      tokenRepository.save.mockResolvedValue(mockToken);
    });

    it('should successfully login with verified email', async () => {
      userRepository.findOne.mockResolvedValue(mockUser);

      const result = await service.login(mockLoginDto);

      expect(result).toBeDefined();
      expect(result.accessToken).toBeDefined();
      // eslint-disable-next-line @typescript-eslint/unbound-method
      expect(userRepository.findOne).toHaveBeenCalledWith({
        where: { email: mockLoginDto.email },
        select: expect.arrayContaining(['isEmailVerified']),
      });
    });

    it('should throw UnauthorizedException if email is not verified', async () => {
      const unverifiedUser = { ...mockUser, isEmailVerified: false };
      userRepository.findOne.mockResolvedValue(unverifiedUser);

      await expect(service.login(mockLoginDto)).rejects.toThrow(
        new UnauthorizedException(
          '이메일 인증이 완료되지 않았습니다. 이메일을 확인하여 계정을 인증해주세요.',
        ),
      );
    });

    it('should throw UnauthorizedException for invalid credentials', async () => {
      userRepository.findOne.mockResolvedValue(null);

      await expect(service.login(mockLoginDto)).rejects.toThrow(
        UnauthorizedException,
      );
    });

    it('should throw UnauthorizedException for invalid password', async () => {
      userRepository.findOne.mockResolvedValue(mockUser);
      mockedBcrypt.compare.mockResolvedValue(false as never);

      await expect(service.login(mockLoginDto)).rejects.toThrow(
        UnauthorizedException,
      );
    });

    it('should throw UnauthorizedException for invalid reCAPTCHA', async () => {
      recaptchaService.verifyToken.mockResolvedValue(false);

      await expect(service.login(mockLoginDto)).rejects.toThrow(
        new UnauthorizedException('reCAPTCHA verification failed'),
      );
    });

    it('should require 2FA when enabled', async () => {
      const twoFactorUser = { ...mockUser, isTwoFactorEnabled: true };
      userRepository.findOne.mockResolvedValue(twoFactorUser);

      await expect(service.login(mockLoginDto)).rejects.toThrow(
        new UnauthorizedException('2FA_REQUIRED'),
      );
    });
  });
});
