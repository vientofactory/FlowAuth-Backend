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

@Entity()
@Index(['code'], { unique: true })
@Index(['client', 'user'])
export class AuthorizationCode {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ type: 'varchar', length: 128, nullable: true })
  code: string;

  @Column()
  expiresAt: Date;

  @Column({ nullable: true })
  redirectUri: string;

  @Column({ type: 'json', nullable: true })
  scopes: string[];

  @Column({ nullable: true })
  state: string;

  @Column({ nullable: true })
  codeChallenge: string;

  @Column({ nullable: true })
  codeChallengeMethod: string;

  @Column({ type: 'tinyint', default: 0 })
  isUsed: boolean;

  @ManyToOne(() => User)
  @JoinColumn()
  user: User;

  @ManyToOne(() => Client)
  @JoinColumn()
  client: Client;

  @CreateDateColumn()
  createdAt: Date;
}
