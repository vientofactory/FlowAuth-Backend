import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  CreateDateColumn,
  UpdateDateColumn,
  Index,
} from 'typeorm';

@Entity()
@Index(['clientId'], { unique: true })
export class Client {
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  clientId: string;

  @Column({ nullable: true })
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

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;
}
