import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  ManyToOne,
  JoinColumn,
  CreateDateColumn,
  Index,
} from 'typeorm';
import { User } from '../user/user.entity';
import { Client } from '../client/client.entity';
import { Exclude } from 'class-transformer';

@Entity()
@Index(['accessToken'], { unique: true })
@Index(['refreshToken'], { unique: true })
@Index(['client', 'user'])
export class Token {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ type: 'varchar', length: 2048 })
  @Exclude()
  accessToken: string;

  @Column({ type: 'varchar', length: 2048, nullable: true })
  @Exclude()
  refreshToken?: string;

  @Column({ type: 'datetime' })
  expiresAt: Date;

  @Column({ type: 'datetime', nullable: true })
  refreshExpiresAt?: Date;

  @Column({ type: 'json', nullable: true })
  scopes?: string[];

  @Column({ type: 'varchar', length: 20, default: 'bearer' })
  tokenType: string;

  @Column({ type: 'tinyint', default: 0 })
  isRevoked: boolean;

  @Column({ type: 'datetime', nullable: true })
  revokedAt?: Date;

  @Column({ type: 'tinyint', default: 0 })
  isRefreshTokenUsed: boolean;

  @ManyToOne(() => User, { nullable: true })
  @JoinColumn()
  user?: User;

  @ManyToOne(() => Client, { nullable: true })
  @JoinColumn()
  client?: Client;

  @CreateDateColumn()
  createdAt: Date;
}
