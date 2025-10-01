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
import { User } from '../auth/user.entity';

@Entity()
@Index(['clientId'], { unique: true })
export class Client {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ type: 'varchar', length: 255 })
  clientId: string;

  @Column({ type: 'varchar', length: 255, nullable: true })
  @Exclude()
  clientSecret?: string;

  @Column({ type: 'json' })
  redirectUris: string[];

  @Column({ type: 'json' })
  grants: string[];

  @Column({ type: 'json', nullable: true })
  scopes?: string[];

  @Column({ type: 'varchar', length: 255 })
  name: string;

  @Column({ type: 'varchar', length: 500, nullable: true })
  description?: string;

  @Column({ type: 'tinyint', default: 1 })
  isActive: boolean;

  @Column({ type: 'tinyint', default: 0 })
  isConfidential: boolean;

  @Column({ type: 'varchar', length: 500, nullable: true })
  logoUri?: string;

  @Column({ type: 'varchar', length: 500, nullable: true })
  termsOfServiceUri?: string;

  @Column({ type: 'varchar', length: 500, nullable: true })
  policyUri?: string;

  @Column({ type: 'int' })
  userId: number;

  @ManyToOne(() => User, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'userId' })
  user: User;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;
}
