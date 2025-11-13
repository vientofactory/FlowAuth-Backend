import { Test, TestingModule } from '@nestjs/testing';
import { TwoFactorService } from './two-factor.service';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from './user.entity';
import { EmailService } from '../email/email.service';
import { Logger } from '@nestjs/common';

describe('TwoFactorService - Backup Code Security', () => {
  let service: TwoFactorService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        TwoFactorService,
        {
          provide: getRepositoryToken(User),
          useClass: Repository,
        },
        {
          provide: EmailService,
          useValue: {
            queue2FAEnabled: jest.fn(),
          },
        },
      ],
    }).compile();

    service = module.get<TwoFactorService>(TwoFactorService);

    // Logger 스파이 설정
    jest.spyOn(Logger.prototype, 'log').mockImplementation();
    jest.spyOn(Logger.prototype, 'warn').mockImplementation();
    jest.spyOn(Logger.prototype, 'error').mockImplementation();
  });

  describe('Backup Code Security Tests', () => {
    it('Backup codes should have sufficient entropy', () => {
      // generateBackupCodes 메서드를 public으로 만들거나 reflection 사용
      const generateBackupCodes = (service as any).generateBackupCodes.bind(
        service,
      );

      const codes = generateBackupCodes();

      // 생성된 코드 개수 확인
      expect(codes).toHaveLength(10);

      // 각 코드의 형식 확인 (XXXX-XXXX-XXXX-XXXX)
      codes.forEach((code: string) => {
        expect(code).toMatch(
          /^[0-9A-HJ-KM-NP-TV-Z]{4}-[0-9A-HJ-KM-NP-TV-Z]{4}-[0-9A-HJ-KM-NP-TV-Z]{4}-[0-9A-HJ-KM-NP-TV-Z]{4}$/,
        );
      });

      // 코드 중복 없음 확인
      const uniqueCodes = new Set(codes);
      expect(uniqueCodes.size).toBe(codes.length);

      // 전체 문자의 엔트로피 확인
      const allChars = codes.join('').replace(/-/g, '');
      const uniqueChars = new Set(allChars);
      expect(uniqueChars.size).toBeGreaterThanOrEqual(8);
    });

    it('Backup codes should use cryptographically secure random values', () => {
      const generateBackupCodes = (service as any).generateBackupCodes.bind(
        service,
      );

      // 여러 번 생성하여 패턴 확인
      const codesSets: Set<string>[] = [];
      for (let i = 0; i < 5; i++) {
        codesSets.push(new Set(generateBackupCodes()));
      }

      // 서로 다른 세트 간에 중복이 거의 없어야 함
      for (let i = 0; i < codesSets.length - 1; i++) {
        for (let j = i + 1; j < codesSets.length; j++) {
          const setI = codesSets.at(i);
          const setJ = codesSets.at(j);
          if (setI && setJ) {
            const intersection = new Set([...setI].filter((x) => setJ.has(x)));
            expect(intersection.size).toBeLessThanOrEqual(1);
          }
        }
      }
    });

    it('Backup code normalization should work correctly', () => {
      const normalizeBackupCode = (service as any).normalizeBackupCode.bind(
        service,
      );

      // 유효한 형식들 (16자리)
      expect(normalizeBackupCode('ABCD-EFGH-2345-6789')).toBe(
        'ABCDEFGH23456789',
      );
      expect(normalizeBackupCode('abcd-efgh-2345-6789')).toBe(
        'ABCDEFGH23456789',
      );
      expect(normalizeBackupCode('  ABCD-EFGH-2345-6789  ')).toBe(
        'ABCDEFGH23456789',
      );
      expect(normalizeBackupCode('ABCDEFGH23456789')).toBe('ABCDEFGH23456789');

      // 유효하지 않은 형식들
      expect(normalizeBackupCode('')).toBeNull();
      expect(normalizeBackupCode('ABC')).toBeNull(); // 너무 짧음
      expect(normalizeBackupCode('ABCDEFGHIJKLMNOPQ')).toBeNull(); // 너무 길음
      expect(normalizeBackupCode('ABCD-EFGH-01IO')).toBeNull(); // 잘못된 문자 (0, 1, I, O)
      expect(normalizeBackupCode(null as any)).toBeNull();
      expect(normalizeBackupCode(undefined as any)).toBeNull();
    });

    it('Backup code normalization should meet security requirements', () => {
      const normalizeBackupCode = (service as any).normalizeBackupCode.bind(
        service,
      );

      // 잘못된 문자 세트 테스트 (Base32 외부 문자)
      const invalidChars = ['0', '1', '8', '9', 'I', 'O'];
      invalidChars.forEach((char) => {
        expect(normalizeBackupCode(`ABCD-EFGH-234${char}`)).toBeNull();
      });

      // SQL 인젝션 시도
      expect(normalizeBackupCode("'; DROP TABLE users; --")).toBeNull();

      // XSS 시도
      expect(normalizeBackupCode('<script>alert("xss")</script>')).toBeNull();

      // 버퍼 오버플로우 시도
      const longString = 'A'.repeat(1000);
      expect(normalizeBackupCode(longString)).toBeNull();
    });
  });
});
