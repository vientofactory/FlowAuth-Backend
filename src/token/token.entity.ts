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
@Index(['accessToken'], { unique: true })
@Index(['refreshToken'], { unique: true })
@Index(['client', 'user'])
export class Token {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ type: 'text', unique: true })
  accessToken: string;

  @Column({ type: 'text', nullable: true, unique: true })
  refreshToken: string;

  @Column()
  expiresAt: Date;

  @Column({ nullable: true })
  refreshExpiresAt: Date;

  @Column('simple-array', { nullable: true })
  scopes: string[];

  @Column({ default: 'bearer' })
  tokenType: string;

  @Column({ default: false })
  isRevoked: boolean;

  @ManyToOne(() => User, { eager: true, nullable: true })
  @JoinColumn()
  user: User | null;

  @ManyToOne(() => Client, { eager: true })
  @JoinColumn()
  client: Client;

  @CreateDateColumn()
  createdAt: Date;
}
