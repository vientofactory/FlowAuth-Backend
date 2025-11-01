import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from './user.entity';
import { PermissionUtils } from '../utils/permission.util';
import { ROLE_PERMISSIONS } from '../constants/auth.constants';
import { CACHE_CONFIG, CACHE_KEYS } from '../constants/cache.constants';
import { CacheManagerService } from '../cache/cache-manager.service';

@Injectable()
export class PermissionsService {
  private readonly logger = new Logger(PermissionsService.name);

  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
    private cacheManagerService: CacheManagerService,
  ) {}

  /**
   * 사용자 권한 조회 (캐싱 적용)
   */
  async getUserPermissions(userId: number): Promise<number> {
    const cacheKey = CACHE_KEYS.auth.permissions(userId);

    // 캐시에서 먼저 조회
    const cached =
      await this.cacheManagerService.getCacheValue<number>(cacheKey);
    if (cached !== undefined) {
      return cached;
    }

    // 캐시에 없으면 DB 조회
    const user = await this.userRepository.findOne({
      where: { id: userId },
      select: ['permissions'],
    });

    if (!user) {
      throw new Error('사용자를 찾을 수 없습니다.');
    }

    // 결과를 캐시에 저장 (5분 TTL)
    await this.cacheManagerService.setCacheValue(
      cacheKey,
      user.permissions,
      CACHE_CONFIG.TTL.USER_PERMISSIONS,
    );
    return user.permissions;
  }

  /**
   * 사용자 권한 설정
   */
  async setUserPermissions(userId: number, permissions: number): Promise<void> {
    const oldPermissions = await this.getUserPermissions(userId);
    await this.userRepository.update(userId, { permissions });
    // 권한 변경 시 캐시 무효화
    await this.cacheManagerService.delCacheKey(
      CACHE_KEYS.auth.permissions(userId),
    );

    // 권한 변경 로그
    this.logger.log(
      `User permissions updated - UserID: ${userId}, ` +
        `Old: ${PermissionUtils.permissionsToHex(oldPermissions)}, ` +
        `New: ${PermissionUtils.permissionsToHex(permissions)}`,
    );
  }

  /**
   * 사용자에게 권한 추가
   */
  async addUserPermissions(
    userId: number,
    permissionsToAdd: number[],
  ): Promise<void> {
    const currentPermissions = await this.getUserPermissions(userId);
    const newPermissions = PermissionUtils.addPermissions(
      currentPermissions,
      permissionsToAdd,
    );
    await this.setUserPermissions(userId, newPermissions);
  }

  /**
   * 사용자 권한 제거
   */
  async removeUserPermissions(
    userId: number,
    permissionsToRemove: number[],
  ): Promise<void> {
    const currentPermissions = await this.getUserPermissions(userId);
    const newPermissions = PermissionUtils.removePermissions(
      currentPermissions,
      permissionsToRemove,
    );
    await this.setUserPermissions(userId, newPermissions);
  }

  /**
   * 사용자 권한 확인
   */
  async userHasPermission(
    userId: number,
    permission: number,
  ): Promise<boolean> {
    const userPermissions = await this.getUserPermissions(userId);
    return PermissionUtils.hasPermission(userPermissions, permission);
  }

  /**
   * 사용자 권한 목록 조회
   */
  async getUserPermissionNames(userId: number): Promise<string[]> {
    const userPermissions = await this.getUserPermissions(userId);
    return PermissionUtils.getPermissionNames(userPermissions);
  }

  /**
   * 사용자 역할 설정
   */
  async setUserRole(userId: number, role: string): Promise<void> {
    const rolePermissions =
      ROLE_PERMISSIONS[role as keyof typeof ROLE_PERMISSIONS];
    if (!rolePermissions) {
      throw new Error('유효하지 않은 역할입니다.');
    }
    const permissions = rolePermissions.reduce((acc, perm) => acc | perm, 0);
    await this.setUserPermissions(userId, permissions);
  }

  /**
   * 사용자 역할 조회
   */
  async getUserRole(userId: number): Promise<string> {
    const userPermissions = await this.getUserPermissions(userId);
    return PermissionUtils.getRoleName(userPermissions);
  }

  /**
   * 관리자 권한 확인
   */
  async isUserAdmin(userId: number): Promise<boolean> {
    const userPermissions = await this.getUserPermissions(userId);
    return PermissionUtils.isAdmin(userPermissions);
  }

  /**
   * 사용자 권한 캐시 무효화
   */
  async invalidateUserCache(userId: number): Promise<void> {
    await this.cacheManagerService.delCacheKey(
      CACHE_KEYS.auth.permissions(userId),
    );
  }

  /**
   * 기본 권한으로 초기화
   */
  async resetUserToDefaultPermissions(userId: number): Promise<void> {
    await this.setUserPermissions(
      userId,
      PermissionUtils.getDefaultPermissions(),
    );
  }
}
