import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  CreateDateColumn,
  UpdateDateColumn,
} from 'typeorm';
import { Exclude } from 'class-transformer';
import { USER_TYPES } from '../constants/auth.constants';

@Entity()
export class User {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ type: 'varchar', length: 100 })
  username: string;

  @Column({ type: 'varchar', length: 255 })
  email: string;

  @Column({ type: 'varchar', length: 255 })
  @Exclude()
  password: string;

  @Column({ type: 'varchar', length: 100, nullable: true })
  firstName?: string;

  @Column({ type: 'varchar', length: 100, nullable: true })
  lastName?: string;

  @Column({ type: 'varchar', length: 20, default: USER_TYPES.REGULAR })
  userType: USER_TYPES;

  @Column({ type: 'tinyint', default: 0 })
  isEmailVerified: boolean;

  @Column({ type: 'bigint', default: 1 }) // 기본적으로 READ_USER 권한
  permissions: number;

  @Column({ type: 'datetime', nullable: true })
  lastLoginAt?: Date;

  // 2FA 관련 필드들
  @Column({ type: 'varchar', length: 255, nullable: true })
  @Exclude()
  twoFactorSecret?: string;

  @Column({ type: 'tinyint', default: 0 })
  isTwoFactorEnabled: boolean;

  @Column({ type: 'text', nullable: true })
  @Exclude()
  backupCodes?: string[];

  @Column({ type: 'tinyint', default: 1 })
  isActive: boolean;

  @Column({ type: 'text', nullable: true })
  avatar?: string | null;

  @Column({ type: 'text', nullable: true })
  bio?: string;

  @Column({ type: 'text', nullable: true })
  website?: string;

  @Column({ type: 'text', nullable: true })
  location?: string;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;
}
