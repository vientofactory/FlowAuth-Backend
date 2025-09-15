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

  @Column({ type: 'varchar', length: 2048, nullable: true })
  accessToken: string;

  @Column({ type: 'varchar', length: 2048, nullable: true })
  refreshToken: string;

  @Column()
  expiresAt: Date;

  @Column({ nullable: true })
  refreshExpiresAt: Date;

  @Column({ type: 'json', nullable: true })
  scopes: string[];

  @Column({ default: 'bearer' })
  tokenType: string;

  @Column({ type: 'tinyint', default: 0 })
  isRevoked: boolean;

  @ManyToOne(() => User, { nullable: true })
  @JoinColumn()
  user: User | null;

  @ManyToOne(() => Client)
  @JoinColumn()
  client: Client;

  @CreateDateColumn()
  createdAt: Date;
}
