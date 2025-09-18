import { MigrationInterface, QueryRunner } from 'typeorm';

export class OptimizeDatabaseSchema1734735885000 implements MigrationInterface {
  name = 'OptimizeDatabaseSchema1734735885000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    // Optimize Token table
    await queryRunner.query(`
      ALTER TABLE \`token\`
      MODIFY COLUMN \`accessToken\` VARCHAR(2048) NOT NULL,
      MODIFY COLUMN \`refreshToken\` VARCHAR(2048) NULL,
      MODIFY COLUMN \`scopes\` JSON NULL,
      MODIFY COLUMN \`isRevoked\` TINYINT(1) DEFAULT 0
    `);

    // Optimize AuthorizationCode table
    await queryRunner.query(`
      ALTER TABLE \`authorization_code\`
      MODIFY COLUMN \`code\` VARCHAR(128) NOT NULL,
      MODIFY COLUMN \`scopes\` JSON NULL,
      MODIFY COLUMN \`isUsed\` TINYINT(1) DEFAULT 0
    `);

    // Optimize Client table
    await queryRunner.query(`
      ALTER TABLE \`client\`
      MODIFY COLUMN \`redirectUris\` JSON NOT NULL,
      MODIFY COLUMN \`grants\` JSON NOT NULL,
      MODIFY COLUMN \`scopes\` JSON NULL,
      MODIFY COLUMN \`isActive\` TINYINT(1) DEFAULT 1,
      MODIFY COLUMN \`isConfidential\` TINYINT(1) DEFAULT 0
    `);

    // Optimize User table
    await queryRunner.query(`
      ALTER TABLE \`user\`
      MODIFY COLUMN \`username\` VARCHAR(100) NOT NULL,
      MODIFY COLUMN \`email\` VARCHAR(255) NOT NULL,
      MODIFY COLUMN \`isEmailVerified\` TINYINT(1) DEFAULT 0
    `);

    // Add performance indexes
    await queryRunner.query(`
      CREATE INDEX \`IDX_token_expires_at\` ON \`token\` (\`expiresAt\`)
    `);

    await queryRunner.query(`
      CREATE INDEX \`IDX_token_refresh_expires_at\` ON \`token\` (\`refreshExpiresAt\`)
    `);

    await queryRunner.query(`
      CREATE INDEX \`IDX_authorization_code_expires_at\` ON \`authorization_code\` (\`expiresAt\`)
    `);

    await queryRunner.query(`
      CREATE INDEX \`IDX_user_created_at\` ON \`user\` (\`createdAt\`)
    `);

    await queryRunner.query(`
      CREATE INDEX \`IDX_token_created_at\` ON \`token\` (\`createdAt\`)
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    // Revert indexes
    await queryRunner.query(`
      DROP INDEX \`IDX_token_expires_at\` ON \`token\`
    `);

    await queryRunner.query(`
      DROP INDEX \`IDX_token_refresh_expires_at\` ON \`token\`
    `);

    await queryRunner.query(`
      DROP INDEX \`IDX_authorization_code_expires_at\` ON \`authorization_code\`
    `);

    await queryRunner.query(`
      DROP INDEX \`IDX_user_created_at\` ON \`user\`
    `);

    await queryRunner.query(`
      DROP INDEX \`IDX_token_created_at\` ON \`token\`
    `);

    // Revert column optimizations
    await queryRunner.query(`
      ALTER TABLE \`token\`
      MODIFY COLUMN \`accessToken\` TEXT NOT NULL,
      MODIFY COLUMN \`refreshToken\` TEXT NULL,
      MODIFY COLUMN \`scopes\` TEXT NULL,
      MODIFY COLUMN \`isRevoked\` TINYINT(1) DEFAULT 0
    `);

    await queryRunner.query(`
      ALTER TABLE \`authorization_code\`
      MODIFY COLUMN \`code\` VARCHAR(255) NOT NULL,
      MODIFY COLUMN \`scopes\` TEXT NULL,
      MODIFY COLUMN \`isUsed\` TINYINT(1) DEFAULT 0
    `);

    await queryRunner.query(`
      ALTER TABLE \`client\`
      MODIFY COLUMN \`redirectUris\` TEXT NOT NULL,
      MODIFY COLUMN \`grants\` TEXT NOT NULL,
      MODIFY COLUMN \`scopes\` TEXT NULL,
      MODIFY COLUMN \`isActive\` TINYINT(1) DEFAULT 1,
      MODIFY COLUMN \`isConfidential\` TINYINT(1) DEFAULT 0
    `);

    await queryRunner.query(`
      ALTER TABLE \`user\`
      MODIFY COLUMN \`username\` VARCHAR(255) NOT NULL,
      MODIFY COLUMN \`email\` VARCHAR(255) NOT NULL,
      MODIFY COLUMN \`isEmailVerified\` TINYINT(1) DEFAULT 0
    `);
  }
}
