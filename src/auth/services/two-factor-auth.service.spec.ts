import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { JwtService } from '@nestjs/jwt';
import { UnauthorizedException } from '@nestjs/common';

import { TwoFactorAuthService } from './two-factor-auth.service';
import { User } from '../user.entity';
import { Token } from '../../oauth2/token.entity';
import { TwoFactorService } from '../two-factor.service';
import { AUTH_ERROR_MESSAGES } from '../../constants/auth.constants';

describe('TwoFactorAuthService', () => {
  let service: TwoFactorAuthService;
  let userRepository: jest.Mocked<Repository<User>>;
  let tokenRepository: jest.Mocked<Repository<Token>>;
  let jwtService: jest.Mocked<JwtService>;
  let twoFactorService: jest.Mocked<TwoFactorService>;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        TwoFactorAuthService,
        {
          provide: getRepositoryToken(User),
          useValue: {
            findOne: jest.fn(),
          },
        },
        {
          provide: getRepositoryToken(Token),
          useValue: {
            create: jest.fn(),
            save: jest.fn(),
          },
        },
        {
          provide: JwtService,
          useValue: {
            sign: jest.fn(),
          },
        },
        {
          provide: TwoFactorService,
          useValue: {
            verifyToken: jest.fn(),
            verifyBackupCode: jest.fn(),
          },
        },
      ],
    })
      .overrideProvider(TwoFactorService)
      .useValue({
        verifyToken: jest.fn(),
        verifyBackupCode: jest.fn(),
      })
      .compile();

    service = module.get<TwoFactorAuthService>(TwoFactorAuthService);
    userRepository = module.get(getRepositoryToken(User));
    tokenRepository = module.get(getRepositoryToken(Token));
    jwtService = module.get(JwtService);
    twoFactorService = module.get(TwoFactorService);
  });

  describe('verifyTwoFactorToken', () => {
    const mockUser = {
      id: 1,
      email: 'test@example.com',
      username: 'testuser',
      password: 'hashedPassword',
      firstName: 'Test',
      lastName: 'User',
      permissions: 1,
      userType: 'regular',
      isTwoFactorEnabled: true,
      twoFactorSecret: 'secret123',
      isEmailVerified: true,
      avatar: null,
      isActive: true,
      createdAt: new Date(),
      updatedAt: new Date(),
    } as User;

    beforeEach(() => {
      jwtService.sign.mockReturnValue('jwt-token');
      const mockToken = { id: 123 } as Token;
      tokenRepository.create.mockReturnValue(mockToken);
      tokenRepository.save.mockResolvedValue(mockToken);
    });

    it('should successfully verify 2FA token with verified email', async () => {
      userRepository.findOne.mockResolvedValue(mockUser);
      twoFactorService.verifyToken.mockResolvedValue(true);

      const result = await service.verifyTwoFactorToken(
        'test@example.com',
        '123456',
      );

      expect(result).toBeDefined();
      expect(result.accessToken).toBe('jwt-token');
      // eslint-disable-next-line @typescript-eslint/unbound-method
      expect(userRepository.findOne).toHaveBeenCalledWith({
        where: { email: 'test@example.com' },
        select: expect.arrayContaining(['isEmailVerified']),
      });
      // eslint-disable-next-line @typescript-eslint/unbound-method
      expect(twoFactorService.verifyToken).toHaveBeenCalledWith(1, '123456');
    });

    it('should throw UnauthorizedException if email is not verified', async () => {
      const unverifiedUser = { ...mockUser, isEmailVerified: false };
      userRepository.findOne.mockResolvedValue(unverifiedUser);

      await expect(
        service.verifyTwoFactorToken('test@example.com', '123456'),
      ).rejects.toThrow(
        new UnauthorizedException(
          '이메일 인증이 완료되지 않았습니다. 이메일을 확인하여 계정을 인증해주세요.',
        ),
      );
    });

    it('should throw UnauthorizedException if user not found', async () => {
      userRepository.findOne.mockResolvedValue(null);

      await expect(
        service.verifyTwoFactorToken('test@example.com', '123456'),
      ).rejects.toThrow(
        new UnauthorizedException(AUTH_ERROR_MESSAGES.INVALID_CREDENTIALS),
      );
    });

    it('should throw UnauthorizedException if 2FA is not enabled', async () => {
      const userWithout2FA = {
        ...mockUser,
        isTwoFactorEnabled: false,
        twoFactorSecret: undefined,
      };
      userRepository.findOne.mockResolvedValue(userWithout2FA);

      await expect(
        service.verifyTwoFactorToken('test@example.com', '123456'),
      ).rejects.toThrow(
        new UnauthorizedException(AUTH_ERROR_MESSAGES.TWO_FACTOR_NOT_ENABLED),
      );
    });

    it('should throw UnauthorizedException if token is invalid', async () => {
      userRepository.findOne.mockResolvedValue(mockUser);
      twoFactorService.verifyToken.mockResolvedValue(false);

      await expect(
        service.verifyTwoFactorToken('test@example.com', '123456'),
      ).rejects.toThrow(
        new UnauthorizedException(AUTH_ERROR_MESSAGES.INVALID_TWO_FACTOR_TOKEN),
      );
    });
  });

  describe('verifyBackupCode', () => {
    const mockUser = {
      id: 1,
      email: 'test@example.com',
      username: 'testuser',
      password: 'hashedPassword',
      firstName: 'Test',
      lastName: 'User',
      permissions: 1,
      userType: 'regular',
      isTwoFactorEnabled: true,
      isEmailVerified: true,
      avatar: null,
      isActive: true,
      createdAt: new Date(),
      updatedAt: new Date(),
    } as User;

    beforeEach(() => {
      jwtService.sign.mockReturnValue('jwt-token');
      const mockToken = { id: 123 } as Token;
      tokenRepository.create.mockReturnValue(mockToken);
      tokenRepository.save.mockResolvedValue(mockToken);
    });

    it('should successfully verify backup code with verified email', async () => {
      userRepository.findOne.mockResolvedValue(mockUser);
      twoFactorService.verifyBackupCode.mockResolvedValue(true);

      const result = await service.verifyBackupCode(
        'test@example.com',
        'backup-code-123',
      );

      expect(result).toBeDefined();
      expect(result.accessToken).toBe('jwt-token');
      // eslint-disable-next-line @typescript-eslint/unbound-method
      expect(userRepository.findOne).toHaveBeenCalledWith({
        where: { email: 'test@example.com' },
        select: expect.arrayContaining(['isEmailVerified']),
      });
      // eslint-disable-next-line @typescript-eslint/unbound-method
      expect(twoFactorService.verifyBackupCode).toHaveBeenCalledWith(
        1,
        'backup-code-123',
      );
    });

    it('should throw UnauthorizedException if email is not verified', async () => {
      const unverifiedUser = { ...mockUser, isEmailVerified: false };
      userRepository.findOne.mockResolvedValue(unverifiedUser);

      await expect(
        service.verifyBackupCode('test@example.com', 'backup-code-123'),
      ).rejects.toThrow(
        new UnauthorizedException(
          '이메일 인증이 완료되지 않았습니다. 이메일을 확인하여 계정을 인증해주세요.',
        ),
      );
    });

    it('should throw UnauthorizedException if backup code is invalid', async () => {
      userRepository.findOne.mockResolvedValue(mockUser);
      twoFactorService.verifyBackupCode.mockResolvedValue(false);

      await expect(
        service.verifyBackupCode('test@example.com', 'backup-code-123'),
      ).rejects.toThrow(
        new UnauthorizedException(AUTH_ERROR_MESSAGES.INVALID_BACKUP_CODE),
      );
    });
  });
});
