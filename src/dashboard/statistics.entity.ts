import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  Index,
  CreateDateColumn,
} from 'typeorm';

export enum TokenEventType {
  ISSUED = 'issued',
  REVOKED = 'revoked',
  EXPIRED = 'expired',
}

export enum ScopeEventType {
  GRANTED = 'granted',
  REVOKED = 'revoked',
}

@Entity('token_statistics')
@Index(['userId', 'clientId', 'eventType', 'eventDate'])
@Index(['eventDate'])
export class TokenStatistics {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ type: 'int' })
  @Index()
  userId: number;

  @Column({ type: 'int', nullable: true })
  @Index()
  clientId: number;

  @Column({
    type: 'enum',
    enum: TokenEventType,
  })
  eventType: TokenEventType;

  @Column({ type: 'date' })
  @Index()
  eventDate: Date;

  @Column({ type: 'int', default: 1 })
  count: number;

  @Column({ type: 'varchar', length: 500, nullable: true })
  revokedReason: string;

  @CreateDateColumn()
  createdAt: Date;
}

@Entity('scope_statistics')
@Index(['userId', 'scope', 'eventType', 'eventDate'])
@Index(['eventDate'])
export class ScopeStatistics {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ type: 'int' })
  @Index()
  userId: number;

  @Column({ type: 'varchar', length: 100 })
  @Index()
  scope: string;

  @Column({
    type: 'enum',
    enum: ScopeEventType,
  })
  eventType: ScopeEventType;

  @Column({ type: 'date' })
  @Index()
  eventDate: Date;

  @Column({ type: 'int', default: 1 })
  count: number;

  @CreateDateColumn()
  createdAt: Date;
}

@Entity('client_statistics')
@Index(['userId', 'clientId', 'eventDate'])
@Index(['eventDate'])
export class ClientStatistics {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ type: 'int' })
  @Index()
  userId: number;

  @Column({ type: 'int' })
  @Index()
  clientId: number;

  @Column({ type: 'varchar', length: 255 })
  clientName: string;

  @Column({ type: 'date' })
  @Index()
  eventDate: Date;

  @Column({ type: 'int', default: 0 })
  tokensIssued: number;

  @Column({ type: 'int', default: 0 })
  tokensActive: number;

  @Column({ type: 'int', default: 0 })
  tokensExpired: number;

  @Column({ type: 'int', default: 0 })
  tokensRevoked: number;

  @CreateDateColumn()
  createdAt: Date;
}
