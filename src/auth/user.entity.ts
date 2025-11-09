import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  CreateDateColumn,
  UpdateDateColumn,
  Index,
} from 'typeorm';
import { Exclude } from 'class-transformer';
import { USER_TYPES } from '../constants/auth.constants';

@Entity()
@Index(['username'], { unique: true })
@Index(['email'], { unique: true })
@Index(['id', 'isActive'])
@Index(['userId'], { unique: true })
export class User {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ type: 'varchar', length: 255, unique: true, nullable: true })
  userId?: string;

  @Column({ type: 'varchar', length: 100, unique: true })
  username: string;

  @Column({ type: 'varchar', length: 255, unique: true })
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

  @Column({
    type: 'bigint',
    default: 1,
    transformer: {
      to: (value: number) => value,
      from: (value: string | number) =>
        typeof value === 'string' ? parseInt(value, 10) : value,
    },
  }) // 기본적으로 READ_USER 권한
  permissions: number;

  @Column({ type: 'datetime', nullable: true })
  lastLoginAt?: Date;

  // 2FA 관련 필드들
  @Column({ type: 'varchar', length: 255, nullable: true })
  @Exclude()
  twoFactorSecret?: string | null;

  @Column({ type: 'tinyint', default: 0 })
  isTwoFactorEnabled: boolean;

  @Column({
    type: 'json',
    nullable: true,
    transformer: {
      to: (value: string[] | null) => value,
      from: (value: string | null) => {
        if (value === null || value === undefined) return null;
        try {
          return typeof value === 'string' ? JSON.parse(value) : value;
        } catch {
          return null;
        }
      },
    },
  })
  @Exclude()
  backupCodes?: string[] | null;

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
