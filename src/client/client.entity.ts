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

  @Column({ unique: true })
  clientId: string;

  @Column()
  clientSecret: string;

  @Column('simple-array')
  redirectUris: string[];

  @Column('simple-array')
  grants: string[];

  @Column('simple-array', { nullable: true })
  scopes: string[];

  @Column()
  name: string;

  @Column({ nullable: true })
  description: string;

  @Column({ default: true })
  isActive: boolean;

  @Column({ default: false })
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
