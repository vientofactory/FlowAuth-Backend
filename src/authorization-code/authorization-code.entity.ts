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

  @Column({ unique: true })
  code: string;

  @Column()
  expiresAt: Date;

  @Column({ nullable: true })
  redirectUri: string;

  @Column('simple-array', { nullable: true })
  scopes: string[];

  @Column({ nullable: true })
  state: string;

  @Column({ nullable: true })
  codeChallenge: string;

  @Column({ nullable: true })
  codeChallengeMethod: string;

  @Column({ default: false })
  isUsed: boolean;

  @ManyToOne(() => User, { eager: true })
  @JoinColumn()
  user: User;

  @ManyToOne(() => Client, { eager: true })
  @JoinColumn()
  client: Client;

  @CreateDateColumn()
  createdAt: Date;
}
