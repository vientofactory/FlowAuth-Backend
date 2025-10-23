import {
  Injectable,
  UnauthorizedException,
  BadRequestException,
  ConflictException,
  Inject,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import type { Cache } from 'cache-manager';
import * as bcrypt from 'bcrypt';
import { User } from '../auth/user.entity';
import { UserManagementService } from '../auth/services/user-management.service';
import { AUTH_CONSTANTS } from '../constants/auth.constants';

@Injectable()
export class ProfileService {
  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
    @Inject(CACHE_MANAGER)
    private cacheManager: Cache,
    private userManagementService: UserManagementService,
  ) {}

  async findById(id: number): Promise<User> {
    const cacheKey = `user:${id}`;

    // 캐시에서 먼저 조회
    const cached = await this.cacheManager.get<User>(cacheKey);
    if (cached) {
      return cached;
    }

    // 캐시에 없으면 DB 조회
    const user = await this.userRepository.findOne({ where: { id } });

    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    // 결과를 캐시에 저장 (10분 TTL)
    await this.cacheManager.set(cacheKey, user, 600000);
    return user;
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
    const allowedFields = [
      'firstName',
      'lastName',
      'username',
      'bio',
      'website',
      'location',
    ] as const;
    const filteredData: Partial<
      Pick<
        User,
        'firstName' | 'lastName' | 'username' | 'bio' | 'website' | 'location'
      >
    > = {};

    // 안전한 객체 할당을 위한 helper 함수
    const safeAssign = (
      key: keyof typeof filteredData,
      value: string | undefined,
    ) => {
      if (key === 'firstName') filteredData.firstName = value as string;
      else if (key === 'lastName') filteredData.lastName = value as string;
      else if (key === 'username') filteredData.username = value as string;
      else if (key === 'bio') filteredData.bio = value;
      else if (key === 'website') filteredData.website = value;
      else if (key === 'location') filteredData.location = value;
    };

    // 입력 데이터 유효성 검사 및 필터링
    for (const field of allowedFields) {
      if (
        Object.prototype.hasOwnProperty.call(updateData, field) &&
        // eslint-disable-next-line security/detect-object-injection
        updateData[field] !== undefined
      ) {
        // Safe property access
        const value =
          field === 'firstName'
            ? updateData.firstName
            : field === 'lastName'
              ? updateData.lastName
              : field === 'username'
                ? updateData.username
                : field === 'bio'
                  ? updateData.bio
                  : field === 'website'
                    ? updateData.website
                    : field === 'location'
                      ? updateData.location
                      : undefined;

        // 필드별 유효성 검사
        if (field === 'username') {
          if (typeof value !== 'string' || value.trim().length === 0) {
            throw new BadRequestException('사용자명은 비어있을 수 없습니다.');
          }
          if (value.length < 3) {
            throw new BadRequestException(
              '사용자명은 최소 3자 이상이어야 합니다.',
            );
          }
          if (value.length > 100) {
            throw new BadRequestException(
              '사용자명은 최대 100자까지 가능합니다.',
            );
          }
          if (!/^[a-zA-Z0-9_-]+$/.test(value)) {
            throw new BadRequestException(
              '사용자명은 영문, 숫자, 하이픈, 언더스코어만 사용할 수 있습니다.',
            );
          }

          // 중복 검사
          const existingUser = await this.userRepository.findOne({
            where: { username: value.trim() },
          });
          if (existingUser && existingUser.id !== userId) {
            throw new ConflictException('이미 사용중인 사용자명입니다.');
          }

          safeAssign(field, value.trim());
        } else if (field === 'firstName' || field === 'lastName') {
          if (value !== null && value !== undefined) {
            if (typeof value !== 'string') {
              throw new BadRequestException(
                `${field === 'firstName' ? '이름' : '성'}은 문자열이어야 합니다.`,
              );
            }
            const trimmedValue = value.trim();
            if (trimmedValue.length === 0) {
              throw new BadRequestException(
                `${field === 'firstName' ? '이름' : '성'}은 비어있을 수 없습니다.`,
              );
            }
            if (trimmedValue.length > 100) {
              throw new BadRequestException(
                `${field === 'firstName' ? '이름' : '성'}은 최대 100자까지 가능합니다.`,
              );
            }
            // 특수문자 제한 (기본적인 문자, 공백, 하이픈만 허용)
            if (!/^[a-zA-Z가-힣\s\-.']+$/.test(trimmedValue)) {
              throw new BadRequestException(
                `${field === 'firstName' ? '이름' : '성'}은 한글, 영문, 공백, 하이픈, 점, 아포스트로피만 사용할 수 있습니다.`,
              );
            }
            safeAssign(field, trimmedValue);
          }
        } else if (field === 'bio') {
          if (value !== null && value !== undefined) {
            if (typeof value !== 'string') {
              throw new BadRequestException('소개글은 문자열이어야 합니다.');
            }
            if (value.length > 500) {
              throw new BadRequestException(
                '소개글은 최대 500자까지 가능합니다.',
              );
            }
            safeAssign(field, value.trim() || undefined);
          } else {
            safeAssign(field, undefined);
          }
        } else if (field === 'website') {
          if (value !== null && value !== undefined) {
            if (typeof value !== 'string') {
              throw new BadRequestException('웹사이트는 문자열이어야 합니다.');
            }
            const trimmedValue = value.trim();
            if (trimmedValue && trimmedValue.length > 0) {
              // URL 형식 검증
              try {
                new URL(trimmedValue);
              } catch {
                throw new BadRequestException(
                  '올바른 URL 형식이 아닙니다. (예: https://example.com)',
                );
              }
              if (trimmedValue.length > 255) {
                throw new BadRequestException(
                  '웹사이트 URL은 최대 255자까지 가능합니다.',
                );
              }
              safeAssign(field, trimmedValue);
            } else {
              safeAssign(field, undefined);
            }
          } else {
            safeAssign(field, undefined);
          }
        } else if (field === 'location') {
          if (value !== null && value !== undefined) {
            if (typeof value !== 'string') {
              throw new BadRequestException('지역은 문자열이어야 합니다.');
            }
            if (value.length > 100) {
              throw new BadRequestException(
                '지역은 최대 100자까지 가능합니다.',
              );
            }
            safeAssign(field, value.trim() || undefined);
          } else {
            safeAssign(field, undefined);
          }
        }
      }
    }

    // 업데이트할 데이터가 있는지 확인
    if (Object.keys(filteredData).length === 0) {
      throw new BadRequestException('업데이트할 데이터가 없습니다.');
    }

    // 데이터베이스 업데이트
    await this.userRepository.update(userId, filteredData);

    // 캐시 무효화
    await this.cacheManager.del(`user:${userId}`);

    // 업데이트된 사용자 정보 조회
    const updatedUser = await this.userRepository.findOne({
      where: { id: userId },
    });

    if (!updatedUser) {
      throw new UnauthorizedException('User not found after update');
    }

    return updatedUser;
  }

  async changePassword(
    userId: number,
    currentPassword: string,
    newPassword: string,
  ): Promise<void> {
    const user = await this.userRepository.findOne({ where: { id: userId } });

    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    // 현재 비밀번호 검증
    const isCurrentPasswordValid = await bcrypt.compare(
      currentPassword,
      user.password,
    );
    if (!isCurrentPasswordValid) {
      throw new BadRequestException('현재 비밀번호가 일치하지 않습니다.');
    }

    // 새 비밀번호 유효성 검사
    if (newPassword.length < 8) {
      throw new BadRequestException('비밀번호는 최소 8자 이상이어야 합니다.');
    }

    // 새 비밀번호 해싱
    const hashedNewPassword = await bcrypt.hash(
      newPassword,
      AUTH_CONSTANTS.BCRYPT_SALT_ROUNDS,
    );

    // 비밀번호 업데이트
    await this.userRepository.update(userId, { password: hashedNewPassword });

    // 캐시 무효화 (비밀번호 변경 시 사용자 정보 캐시도 무효화)
    await this.cacheManager.del(`user:${userId}`);
  }

  async checkUsernameAvailability(
    username: string,
    excludeUserId?: number,
  ): Promise<{ available: boolean; message: string }> {
    // 입력 검증
    if (username?.trim().length === 0) {
      return { available: false, message: '사용자명을 입력해주세요.' };
    }

    const trimmedUsername = username.trim();

    // 길이 검증
    if (trimmedUsername.length < 3) {
      return {
        available: false,
        message: '사용자명은 최소 3자 이상이어야 합니다.',
      };
    }

    if (trimmedUsername.length > 100) {
      return {
        available: false,
        message: '사용자명은 최대 100자까지 가능합니다.',
      };
    }

    // 형식 검증
    if (!/^[a-zA-Z0-9_-]+$/.test(trimmedUsername)) {
      return {
        available: false,
        message:
          '사용자명은 영문, 숫자, 하이픈, 언더스코어만 사용할 수 있습니다.',
      };
    }

    // 중복 체크
    const existingUser = await this.userRepository.findOne({
      where: { username: trimmedUsername },
    });

    if (existingUser && existingUser.id !== excludeUserId) {
      return { available: false, message: '이미 사용중인 사용자명입니다.' };
    }

    return { available: true, message: '사용 가능한 사용자명입니다.' };
  }

  async uploadAvatar(
    userId: number,
    file: Express.Multer.File,
  ): Promise<string> {
    return this.userManagementService.uploadAvatar(userId, file);
  }

  async removeAvatar(userId: number): Promise<void> {
    await this.userManagementService.removeAvatar(userId);
  }
}
