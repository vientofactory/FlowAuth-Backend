import { MigrationInterface, QueryRunner } from 'typeorm';

export class InitialTables1758513256230 implements MigrationInterface {
  name = 'InitialTables1758513256230';

  public async up(queryRunner: QueryRunner): Promise<void> {
    // Create user table
    await queryRunner.query(`
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
        \`createdAt\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
        \`updatedAt\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
        UNIQUE INDEX \`IDX_78a916df40e02a9deb1c4b75ed\` (\`username\`),
        UNIQUE INDEX \`IDX_e12875dfb3b1d92d7d7c5377e2\` (\`email\`),
        PRIMARY KEY (\`id\`)
      ) ENGINE=InnoDB
    `);

    // Create client table
    await queryRunner.query(`
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
        UNIQUE INDEX \`IDX_368e6530b1f2b4af4e96b8c7e4\` (\`clientId\`),
        PRIMARY KEY (\`id\`)
      ) ENGINE=InnoDB
    `);

    // Create scope table
    await queryRunner.query(`
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

    // Create token table
    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS \`token\` (
        \`id\` int NOT NULL AUTO_INCREMENT,
        \`accessToken\` varchar(2048) NOT NULL,
        \`refreshToken\` varchar(2048) NULL,
        \`expiresAt\` datetime NOT NULL,
        \`refreshExpiresAt\` datetime NULL,
        \`scopes\` json NULL,
        \`tokenType\` varchar(20) NOT NULL DEFAULT 'login',
        \`isRevoked\` tinyint NOT NULL DEFAULT 0,
        \`revokedAt\` datetime NULL,
        \`isRefreshTokenUsed\` tinyint NOT NULL DEFAULT 0,
        \`userId\` int NULL,
        \`clientId\` int NULL,
        \`createdAt\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
        UNIQUE INDEX \`IDX_1e4a750a8c1c3e4c8c1c3e4c8c\` (\`accessToken\`),
        UNIQUE INDEX \`IDX_2e4a750a8c1c3e4c8c1c3e4c8c\` (\`refreshToken\`),
        INDEX \`IDX_1f4a750a8c1c3e4c8c1c3e4c8c\` (\`clientId\`, \`userId\`),
        PRIMARY KEY (\`id\`)
      ) ENGINE=InnoDB
    `);

    // Create authorization_code table
    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS \`authorization_code\` (
        \`id\` int NOT NULL AUTO_INCREMENT,
        \`code\` varchar(128) NOT NULL,
        \`expiresAt\` datetime NOT NULL,
        \`redirectUri\` varchar(500) NULL,
        \`scopes\` json NULL,
        \`state\` varchar(256) NULL,
        \`codeChallenge\` varchar(128) NULL,
        \`codeChallengeMethod\` varchar(10) NULL,
        \`isUsed\` tinyint NOT NULL DEFAULT 0,
        \`userId\` int NOT NULL,
        \`clientId\` int NOT NULL,
        \`createdAt\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
        UNIQUE INDEX \`IDX_4a750a8c1c3e4c8c1c3e4c8c1\` (\`code\`),
        INDEX \`IDX_5a750a8c1c3e4c8c1c3e4c8c1\` (\`clientId\`, \`userId\`),
        PRIMARY KEY (\`id\`)
      ) ENGINE=InnoDB
    `);

    // Add foreign key constraints
    await queryRunner.query(`
      ALTER TABLE \`client\`
      ADD CONSTRAINT \`FK_368e6530b1f2b4af4e96b8c7e41\`
      FOREIGN KEY (\`userId\`) REFERENCES \`user\`(\`id\`) ON DELETE CASCADE ON UPDATE NO ACTION
    `);

    await queryRunner.query(`
      ALTER TABLE \`token\`
      ADD CONSTRAINT \`FK_1f4a750a8c1c3e4c8c1c3e4c8c1\`
      FOREIGN KEY (\`userId\`) REFERENCES \`user\`(\`id\`) ON DELETE SET NULL ON UPDATE NO ACTION
    `);

    await queryRunner.query(`
      ALTER TABLE \`token\`
      ADD CONSTRAINT \`FK_2f4a750a8c1c3e4c8c1c3e4c8c2\`
      FOREIGN KEY (\`clientId\`) REFERENCES \`client\`(\`id\`) ON DELETE SET NULL ON UPDATE NO ACTION
    `);

    await queryRunner.query(`
      ALTER TABLE \`authorization_code\`
      ADD CONSTRAINT \`FK_5a750a8c1c3e4c8c1c3e4c8c1\`
      FOREIGN KEY (\`userId\`) REFERENCES \`user\`(\`id\`) ON DELETE CASCADE ON UPDATE NO ACTION
    `);

    await queryRunner.query(`
      ALTER TABLE \`authorization_code\`
      ADD CONSTRAINT \`FK_6a750a8c1c3e4c8c1c3e4c8c2\`
      FOREIGN KEY (\`clientId\`) REFERENCES \`client\`(\`id\`) ON DELETE CASCADE ON UPDATE NO ACTION
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    // Drop foreign key constraints
    await queryRunner.query(
      `ALTER TABLE \`authorization_code\` DROP FOREIGN KEY \`FK_6a750a8c1c3e4c8c1c3e4c8c2\``,
    );
    await queryRunner.query(
      `ALTER TABLE \`authorization_code\` DROP FOREIGN KEY \`FK_5a750a8c1c3e4c8c1c3e4c8c1\``,
    );
    await queryRunner.query(
      `ALTER TABLE \`token\` DROP FOREIGN KEY \`FK_2f4a750a8c1c3e4c8c1c3e4c8c2\``,
    );
    await queryRunner.query(
      `ALTER TABLE \`token\` DROP FOREIGN KEY \`FK_1f4a750a8c1c3e4c8c1c3e4c8c1\``,
    );
    await queryRunner.query(
      `ALTER TABLE \`client\` DROP FOREIGN KEY \`FK_368e6530b1f2b4af4e96b8c7e41\``,
    );

    // Drop tables in reverse order
    await queryRunner.query(`DROP TABLE IF EXISTS \`authorization_code\``);
    await queryRunner.query(`DROP TABLE IF EXISTS \`token\``);
    await queryRunner.query(`DROP TABLE IF EXISTS \`scope\``);
    await queryRunner.query(`DROP TABLE IF EXISTS \`client\``);
    await queryRunner.query(`DROP TABLE IF EXISTS \`user\``);
  }
}
