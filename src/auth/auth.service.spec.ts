import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { AuthService } from './auth.service';
import { User } from './user.entity';
import { Client } from '../oauth2/client.entity';
import { Token } from '../oauth2/token.entity';
import { AuthorizationCode } from '../oauth2/authorization-code.entity';
import { TwoFactorService } from './two-factor.service';
import { FileUploadService } from '../upload/file-upload.service';
import { RecaptchaService } from '../utils/recaptcha.util';
import { UserAuthService } from './services/user-auth.service';
import { ClientAuthService } from './services/client-auth.service';
import { TwoFactorAuthService } from './services/two-factor-auth.service';

describe('AuthService', () => {
  let service: AuthService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        {
          provide: getRepositoryToken(User),
          useValue: {
            findOne: jest.fn(),
            save: jest.fn(),
            create: jest.fn(),
          },
        },
        {
          provide: getRepositoryToken(Client),
          useValue: {
            findOne: jest.fn(),
            save: jest.fn(),
            create: jest.fn(),
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
          provide: getRepositoryToken(AuthorizationCode),
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
            verify: jest.fn(),
          },
        },
        {
          provide: ConfigService,
          useValue: {
            get: jest.fn(),
          },
        },
        {
          provide: FileUploadService,
          useValue: {
            processAvatarImage: jest.fn(),
            processLogoImage: jest.fn(),
          },
        },
        {
          provide: TwoFactorService,
          useValue: {
            generateSecret: jest.fn(),
            verifyToken: jest.fn(),
          },
        },
        {
          provide: RecaptchaService,
          useValue: {
            verify: jest.fn(),
          },
        },
        {
          provide: UserAuthService,
          useValue: {
            register: jest.fn(),
            login: jest.fn(),
          },
        },
        {
          provide: ClientAuthService,
          useValue: {
            createClient: jest.fn(),
            getClients: jest.fn(),
            getClientById: jest.fn(),
          },
        },
        {
          provide: TwoFactorAuthService,
          useValue: {
            verifyTwoFactorToken: jest.fn(),
            verifyBackupCode: jest.fn(),
          },
        },
        {
          provide: CACHE_MANAGER,
          useValue: {
            get: jest.fn(),
            set: jest.fn(),
            del: jest.fn(),
          },
        },
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});
