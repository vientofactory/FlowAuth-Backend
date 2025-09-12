import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  ManyToOne,
  JoinColumn,
  CreateDateColumn,
} from 'typeorm';
import { User } from '../user/user.entity';
import { Client } from '../client/client.entity';

@Entity()
export class AuthorizationCode {
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  code: string;

  @Column()
  expiresAt: Date;

  @Column({ nullable: true })
  redirectUri: string;

  @Column('simple-array', { nullable: true })
  scopes: string[];

  @ManyToOne(() => User)
  @JoinColumn()
  user: User;

  @ManyToOne(() => Client)
  @JoinColumn()
  client: Client;

  @CreateDateColumn()
  createdAt: Date;
}
