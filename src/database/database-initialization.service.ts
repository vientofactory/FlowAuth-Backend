import {
  Injectable,
  Logger,
  OnModuleInit,
  OnModuleDestroy,
} from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import { DataSource } from 'typeorm';
import { SeedService } from './seed.service';

@Injectable()
export class DatabaseInitializationService
  implements OnModuleInit, OnModuleDestroy
{
  private readonly logger = new Logger(DatabaseInitializationService.name);

  constructor(
    @InjectDataSource()
    private readonly dataSource: DataSource,
    private readonly seedService: SeedService,
  ) {}

  async onModuleInit() {
    await this.initializeDatabase();
  }

  private async initializeDatabase() {
    try {
      this.logger.log('Checking database initialization...');

      // 데이터베이스 연결 확인
      await this.checkDatabaseConnection();

      // 필요한 테이블들이 존재하는지 확인
      const tablesExist = await this.checkRequiredTables();

      if (!tablesExist) {
        this.logger.warn(
          'Required tables do not exist. Starting initialization...',
        );
        await this.initializeTables();
      } else {
        this.logger.log('All required tables exist.');
      }

      // 기본 데이터 시드 (항상 실행)
      await this.seedInitialData();

      this.logger.log('Database initialization completed');
    } catch (error) {
      this.logger.error('Error during database initialization:', error);
      throw error;
    }
  }

  private async checkDatabaseConnection(): Promise<void> {
    try {
      await this.dataSource.query('SELECT 1');
      this.logger.log('Database connection successful');
    } catch (error) {
      this.logger.error('Database connection failed:', error);
      throw new Error('Unable to connect to database');
    }
  }

  private async checkRequiredTables(): Promise<boolean> {
    const requiredTables = [
      'user',
      'client',
      'token',
      'authorization_code',
      'scope',
    ];

    try {
      for (const tableName of requiredTables) {
        // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
        const result = await this.dataSource.query(
          `SHOW TABLES LIKE '${tableName}'`,
        );

        // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
        if (!result || result.length === 0) {
          this.logger.warn(`Table '${tableName}' does not exist`);
          return false;
        }
      }

      this.logger.log('All required tables exist');
      return true;
    } catch (error) {
      this.logger.error('Error checking table existence:', error);
      return false;
    }
  }

  private async initializeTables(): Promise<void> {
    this.logger.log('Starting table initialization...');

    try {
      // 사용자 테이블 생성
      await this.dataSource.query(`
        CREATE TABLE IF NOT EXISTS \`user\` (
          \`id\` int NOT NULL AUTO_INCREMENT,
          \`username\` varchar(100) NOT NULL,
          \`email\` varchar(255) NOT NULL,
          \`password\` varchar(255) NOT NULL,
          \`firstName\` varchar(100) NULL,
          \`lastName\` varchar(100) NULL,
          \`userType\` varchar(20) NOT NULL DEFAULT 'regular',
          \`isEmailVerified\` tinyint NOT NULL DEFAULT 0,
          \`permissions\` bigint NOT NULL DEFAULT 1,
          \`lastLoginAt\` datetime NULL,
          \`twoFactorSecret\` varchar(255) NULL,
          \`isTwoFactorEnabled\` tinyint NOT NULL DEFAULT 0,
          \`backupCodes\` json NULL,
          \`isActive\` tinyint NOT NULL DEFAULT 1,
          \`avatar\` text NULL,
          \`bio\` text NULL,
          \`website\` text NULL,
          \`location\` text NULL,
          \`createdAt\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
          \`updatedAt\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
          UNIQUE INDEX \`IDX_78a916df40e02a9deb1c4b75ed\` (\`username\`),
          UNIQUE INDEX \`IDX_e12875dfb3b1d92d7d7c5377e2\` (\`email\`),
          INDEX \`IDX_4a916df40e02a9deb1c4b75eda\` (\`id\`, \`isActive\`),
          PRIMARY KEY (\`id\`)
        ) ENGINE=InnoDB
      `);

      // 클라이언트 테이블 생성
      await this.dataSource.query(`
        CREATE TABLE IF NOT EXISTS \`client\` (
          \`id\` int NOT NULL AUTO_INCREMENT,
          \`clientId\` varchar(255) NOT NULL,
          \`clientSecret\` varchar(255) NULL,
          \`redirectUris\` json NOT NULL,
          \`grants\` json NOT NULL,
          \`scopes\` json NULL,
          \`name\` varchar(255) NOT NULL,
          \`description\` varchar(500) NULL,
          \`isActive\` tinyint NOT NULL DEFAULT 1,
          \`isConfidential\` tinyint NOT NULL DEFAULT 0,
          \`logoUri\` varchar(500) NULL,
          \`termsOfServiceUri\` varchar(500) NULL,
          \`policyUri\` varchar(500) NULL,
          \`userId\` int NOT NULL,
          \`createdAt\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
          \`updatedAt\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
          UNIQUE INDEX \`IDX_368e6530b1f2b4af4e96b8c7e41\` (\`clientId\`),
          INDEX \`IDX_368e6530b1f2b4af4e96b8c7e42\` (\`userId\`),
          PRIMARY KEY (\`id\`)
        ) ENGINE=InnoDB
      `);

      // 스코프 테이블 생성
      await this.dataSource.query(`
        CREATE TABLE IF NOT EXISTS \`scope\` (
          \`id\` int NOT NULL AUTO_INCREMENT,
          \`name\` varchar(255) NOT NULL,
          \`description\` varchar(255) NOT NULL,
          \`isDefault\` tinyint NOT NULL DEFAULT 1,
          \`isActive\` tinyint NOT NULL DEFAULT 1,
          \`createdAt\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
          \`updatedAt\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
          UNIQUE INDEX \`IDX_388c6e6b0e8b8c6b0e8b8c6b0e\` (\`name\`),
          PRIMARY KEY (\`id\`)
        ) ENGINE=InnoDB
      `);

      // 토큰 테이블 생성
      await this.dataSource.query(`
        CREATE TABLE IF NOT EXISTS \`token\` (
          \`id\` int NOT NULL AUTO_INCREMENT,
          \`accessToken\` varchar(2048) NOT NULL,
          \`refreshToken\` varchar(2048) NULL,
          \`expiresAt\` datetime NOT NULL,
          \`refreshExpiresAt\` datetime NULL,
          \`scopes\` json NULL,
          \`tokenType\` varchar(20) NOT NULL DEFAULT 'bearer',
          \`isRevoked\` tinyint NOT NULL DEFAULT 0,
          \`revokedAt\` datetime NULL,
          \`isRefreshTokenUsed\` tinyint NOT NULL DEFAULT 0,
          \`revokedReason\` varchar(255) NULL,
          \`tokenFamily\` varchar(255) NULL,
          \`rotationGeneration\` int NOT NULL DEFAULT 1,
          \`lastUsedAt\` datetime NULL,
          \`lastUsedIp\` varchar(45) NULL,
          \`userId\` int NULL,
          \`clientId\` int NULL,
          \`createdAt\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
          \`updatedAt\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
          UNIQUE INDEX \`IDX_1e4a750a8c1c3e4c8c1c3e4c8c\` (\`accessToken\`),
          UNIQUE INDEX \`IDX_2e4a750a8c1c3e4c8c1c3e4c8c\` (\`refreshToken\`),
          UNIQUE INDEX \`IDX_3e4a750a8c1c3e4c8c1c3e4c8c\` (\`tokenFamily\`, \`rotationGeneration\`),
          INDEX \`IDX_1f4a750a8c1c3e4c8c1c3e4c8c\` (\`clientId\`, \`userId\`),
          INDEX \`IDX_4f4a750a8c1c3e4c8c1c3e4c8c\` (\`isRevoked\`, \`expiresAt\`),
          INDEX \`IDX_5f4a750a8c1c3e4c8c1c3e4c8c\` (\`lastUsedAt\`),
          INDEX \`IDX_6f4a750a8c1c3e4c8c1c3e4c8c\` (\`refreshExpiresAt\`, \`isRefreshTokenUsed\`),
          PRIMARY KEY (\`id\`)
        ) ENGINE=InnoDB
      `);

      // 인증 코드 테이블 생성
      await this.dataSource.query(`
        CREATE TABLE IF NOT EXISTS \`authorization_code\` (
          \`id\` int NOT NULL AUTO_INCREMENT,
          \`code\` varchar(128) NOT NULL,
          \`expiresAt\` datetime NOT NULL,
          \`redirectUri\` varchar(500) NULL,
          \`scopes\` json NULL,
          \`state\` varchar(256) NULL,
          \`codeChallenge\` varchar(128) NULL,
          \`codeChallengeMethod\` varchar(10) NULL,
          \`nonce\` varchar(128) NULL,
          \`authTime\` bigint NULL,
          \`isUsed\` tinyint NOT NULL DEFAULT 0,
          \`userId\` int NOT NULL,
          \`clientId\` int NOT NULL,
          \`createdAt\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
          UNIQUE INDEX \`IDX_4a750a8c1c3e4c8c1c3e4c8c1\` (\`code\`),
          INDEX \`IDX_5a750a8c1c3e4c8c1c3e4c8c1\` (\`clientId\`, \`userId\`),
          PRIMARY KEY (\`id\`)
        ) ENGINE=InnoDB
      `);

      // 외래 키 제약조건 추가
      await this.addForeignKeyConstraints();

      this.logger.log('Table initialization completed');
    } catch (error) {
      this.logger.error('Error during table initialization:', error);
      throw error;
    }
  }

  private async addForeignKeyConstraints(): Promise<void> {
    try {
      // client.userId -> user.id
      await this.dataSource.query(`
        ALTER TABLE \`client\`
        ADD CONSTRAINT \`FK_368e6530b1f2b4af4e96b8c7e41\`
        FOREIGN KEY (\`userId\`) REFERENCES \`user\`(\`id\`) ON DELETE CASCADE ON UPDATE NO ACTION
      `);

      // token.userId -> user.id
      await this.dataSource.query(`
        ALTER TABLE \`token\`
        ADD CONSTRAINT \`FK_1f4a750a8c1c3e4c8c1c3e4c8c1\`
        FOREIGN KEY (\`userId\`) REFERENCES \`user\`(\`id\`) ON DELETE SET NULL ON UPDATE NO ACTION
      `);

      // token.clientId -> client.id
      await this.dataSource.query(`
        ALTER TABLE \`token\`
        ADD CONSTRAINT \`FK_2f4a750a8c1c3e4c8c1c3e4c8c2\`
        FOREIGN KEY (\`clientId\`) REFERENCES \`client\`(\`id\`) ON DELETE SET NULL ON UPDATE NO ACTION
      `);

      // authorization_code.userId -> user.id
      await this.dataSource.query(`
        ALTER TABLE \`authorization_code\`
        ADD CONSTRAINT \`FK_5a750a8c1c3e4c8c1c3e4c8c1\`
        FOREIGN KEY (\`userId\`) REFERENCES \`user\`(\`id\`) ON DELETE CASCADE ON UPDATE NO ACTION
      `);

      // authorization_code.clientId -> client.id
      await this.dataSource.query(`
        ALTER TABLE \`authorization_code\`
        ADD CONSTRAINT \`FK_6a750a8c1c3e4c8c1c3e4c8c2\`
        FOREIGN KEY (\`clientId\`) REFERENCES \`client\`(\`id\`) ON DELETE CASCADE ON UPDATE NO ACTION
      `);

      this.logger.log('Foreign key constraints added successfully');
    } catch (error) {
      // 외래 키가 이미 존재하는 경우 무시
      const err = error as { code?: string; message?: string };
      if (
        err.code !== 'ER_FK_DUP_NAME' &&
        err.code !== 'ER_CANT_DROP_FIELD_OR_KEY'
      ) {
        this.logger.warn(
          'Some errors occurred while adding foreign key constraints (can be ignored):',
          err.message,
        );
      }
    }
  }

  private async seedInitialData(): Promise<void> {
    try {
      this.logger.log('Starting initial data seeding...');
      await this.seedService.seedDatabase();
      this.logger.log('Initial data seeding completed');
    } catch (error) {
      this.logger.error('Error during initial data seeding:', error);
      // 시드 실패는 치명적이지 않으므로 예외를 던지지 않음
    }
  }

  onModuleDestroy(): void {
    this.logger.log('DatabaseInitializationService is shutting down...');
    // DataSource will be automatically closed by TypeORM
  }
}
