import { Entity, Column, PrimaryGeneratedColumn } from 'typeorm';

@Entity()
export class Client {
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  clientId: string;

  @Column()
  clientSecret: string;

  @Column('simple-array')
  redirectUris: string[];

  @Column('simple-array')
  grants: string[];
}
