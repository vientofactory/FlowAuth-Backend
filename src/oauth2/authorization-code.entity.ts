import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  ManyToOne,
  JoinColumn,
  CreateDateColumn,
  Index,
} from 'typeorm';
import { User } from '../auth/user.entity';
import { Client } from './client.entity';

@Entity()
@Index(['code'], { unique: true })
@Index(['client', 'user'])
export class AuthorizationCode {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ type: 'varchar', length: 128 })
  code: string;

  @Column({ type: 'datetime' })
  expiresAt: Date;

  @Column({ type: 'varchar', length: 500, nullable: true })
  redirectUri?: string;

  @Column({ type: 'json', nullable: true })
  scopes?: string[];

  @Column({ type: 'varchar', length: 256, nullable: true })
  state?: string;

  @Column({ type: 'varchar', length: 128, nullable: true })
  codeChallenge?: string;

  @Column({ type: 'varchar', length: 10, nullable: true })
  codeChallengeMethod?: string;

  @Column({ type: 'varchar', length: 128, nullable: true })
  nonce?: string;

  @Column({ type: 'bigint', nullable: true })
  authTime?: number;

  @Column({ type: 'varchar', length: 50, nullable: true })
  responseType?: string;

  @Column({ type: 'tinyint', default: 0 })
  isUsed: boolean;

  @ManyToOne(() => User)
  @JoinColumn()
  user: User;

  @ManyToOne(() => Client, { onDelete: 'CASCADE' })
  @JoinColumn()
  client: Client;

  @CreateDateColumn()
  createdAt: Date;
}
