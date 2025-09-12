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
export class Token {
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  accessToken: string;

  @Column({ nullable: true })
  refreshToken: string;

  @Column()
  expiresAt: Date;

  @Column({ nullable: true })
  refreshExpiresAt: Date;

  @ManyToOne(() => User)
  @JoinColumn()
  user: User;

  @ManyToOne(() => Client)
  @JoinColumn()
  client: Client;

  @CreateDateColumn()
  createdAt: Date;
}
