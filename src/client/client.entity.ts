import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  CreateDateColumn,
  UpdateDateColumn,
  Index,
  ManyToOne,
  JoinColumn,
} from 'typeorm';
import { Exclude } from 'class-transformer';
import { User } from '../user/user.entity';

@Entity()
@Index(['clientId'], { unique: true })
export class Client {
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  clientId: string;

  @Column({ nullable: true })
  @Exclude()
  clientSecret: string;

  @Column({ type: 'json' })
  redirectUris: string[];

  @Column({ type: 'json' })
  grants: string[];

  @Column({ type: 'json', nullable: true })
  scopes: string[];

  @Column()
  name: string;

  @Column({ nullable: true })
  description: string;

  @Column({ type: 'tinyint', default: 1 })
  isActive: boolean;

  @Column({ type: 'tinyint', default: 0 })
  isConfidential: boolean;

  @Column({ nullable: true })
  logoUri: string;

  @Column({ nullable: true })
  termsOfServiceUri: string;

  @Column({ nullable: true })
  policyUri: string;

  @Column()
  userId: number;

  @ManyToOne(() => User, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'userId' })
  user: User;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;
}
