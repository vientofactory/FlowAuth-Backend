import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from '../user/user.entity';
import { PermissionUtils } from '../utils/permission.util';
import { ROLES } from '../constants/auth.constants';

@Injectable()
export class PermissionsService {
  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
  ) {}

  /**
   * 사용자 권한 조회
   */
  async getUserPermissions(userId: number): Promise<number> {
    const user = await this.userRepository.findOne({
      where: { id: userId },
      select: ['permissions'],
    });

    if (!user) {
      throw new Error('사용자를 찾을 수 없습니다.');
    }

    return user.permissions;
  }

  /**
   * 사용자 권한 설정
   */
  async setUserPermissions(userId: number, permissions: number): Promise<void> {
    await this.userRepository.update(userId, { permissions });
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
  async setUserRole(userId: number, role: number): Promise<void> {
    await this.setUserPermissions(userId, role);
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
   * 기본 권한으로 초기화
   */
  async resetUserToDefaultPermissions(userId: number): Promise<void> {
    await this.setUserPermissions(userId, ROLES.USER);
  }
}
