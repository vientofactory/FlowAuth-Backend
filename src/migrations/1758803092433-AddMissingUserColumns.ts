import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddMissingUserColumns1758803092433 implements MigrationInterface {
  name = 'AddMissingUserColumns1758803092433';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `ALTER TABLE \`user\` CHANGE \`firstName\` \`firstName\` varchar(100) NULL`,
    );
    await queryRunner.query(
      `ALTER TABLE \`user\` CHANGE \`lastName\` \`lastName\` varchar(100) NULL`,
    );
    await queryRunner.query(
      `ALTER TABLE \`user\` CHANGE \`lastLoginAt\` \`lastLoginAt\` datetime NULL`,
    );
    await queryRunner.query(
      `ALTER TABLE \`user\` CHANGE \`twoFactorSecret\` \`twoFactorSecret\` varchar(255) NULL`,
    );
    await queryRunner.query(`ALTER TABLE \`user\` DROP COLUMN \`backupCodes\``);
    await queryRunner.query(
      `ALTER TABLE \`user\` ADD \`backupCodes\` json NULL`,
    );
    await queryRunner.query(
      `ALTER TABLE \`user\` CHANGE \`avatar\` \`avatar\` varchar(500) NULL`,
    );
    await queryRunner.query(
      `ALTER TABLE \`user\` CHANGE \`bio\` \`bio\` text NULL`,
    );
    await queryRunner.query(
      `ALTER TABLE \`user\` CHANGE \`website\` \`website\` varchar(255) NULL`,
    );
    await queryRunner.query(
      `ALTER TABLE \`user\` CHANGE \`location\` \`location\` varchar(255) NULL`,
    );
    await queryRunner.query(
      `ALTER TABLE \`client\` CHANGE \`clientSecret\` \`clientSecret\` varchar(255) NULL`,
    );
    await queryRunner.query(`ALTER TABLE \`client\` DROP COLUMN \`scopes\``);
    await queryRunner.query(`ALTER TABLE \`client\` ADD \`scopes\` json NULL`);
    await queryRunner.query(
      `ALTER TABLE \`client\` CHANGE \`description\` \`description\` varchar(500) NULL`,
    );
    await queryRunner.query(
      `ALTER TABLE \`client\` CHANGE \`logoUri\` \`logoUri\` varchar(500) NULL`,
    );
    await queryRunner.query(
      `ALTER TABLE \`client\` CHANGE \`termsOfServiceUri\` \`termsOfServiceUri\` varchar(500) NULL`,
    );
    await queryRunner.query(
      `ALTER TABLE \`client\` CHANGE \`policyUri\` \`policyUri\` varchar(500) NULL`,
    );
    await queryRunner.query(
      `ALTER TABLE \`token\` DROP FOREIGN KEY \`FK_94f168faad896c0786646fa3d4a\``,
    );
    await queryRunner.query(
      `ALTER TABLE \`token\` DROP FOREIGN KEY \`FK_8139f8b076cfd8723e992c9d9ff\``,
    );
    await queryRunner.query(
      `DROP INDEX \`IDX_4970f47b75d7f9a7a05b21af4c\` ON \`token\``,
    );
    await queryRunner.query(
      `ALTER TABLE \`token\` CHANGE \`refreshToken\` \`refreshToken\` varchar(2048) NULL`,
    );
    await queryRunner.query(
      `ALTER TABLE \`token\` CHANGE \`refreshExpiresAt\` \`refreshExpiresAt\` datetime NULL`,
    );
    await queryRunner.query(`ALTER TABLE \`token\` DROP COLUMN \`scopes\``);
    await queryRunner.query(`ALTER TABLE \`token\` ADD \`scopes\` json NULL`);
    await queryRunner.query(
      `ALTER TABLE \`token\` CHANGE \`revokedAt\` \`revokedAt\` datetime NULL`,
    );
    await queryRunner.query(
      `ALTER TABLE \`token\` CHANGE \`userId\` \`userId\` int NULL`,
    );
    await queryRunner.query(
      `ALTER TABLE \`token\` CHANGE \`clientId\` \`clientId\` int NULL`,
    );
    await queryRunner.query(
      `ALTER TABLE \`authorization_code\` DROP FOREIGN KEY \`FK_c84c3d4d0e6344f36785f679e47\``,
    );
    await queryRunner.query(
      `ALTER TABLE \`authorization_code\` DROP FOREIGN KEY \`FK_ffbeadc85eea5dabbbcaf4f6b0e\``,
    );
    await queryRunner.query(
      `DROP INDEX \`IDX_95b8d1a91ad5a739f80fade352\` ON \`authorization_code\``,
    );
    await queryRunner.query(
      `ALTER TABLE \`authorization_code\` CHANGE \`redirectUri\` \`redirectUri\` varchar(500) NULL`,
    );
    await queryRunner.query(
      `ALTER TABLE \`authorization_code\` DROP COLUMN \`scopes\``,
    );
    await queryRunner.query(
      `ALTER TABLE \`authorization_code\` ADD \`scopes\` json NULL`,
    );
    await queryRunner.query(
      `ALTER TABLE \`authorization_code\` CHANGE \`state\` \`state\` varchar(256) NULL`,
    );
    await queryRunner.query(
      `ALTER TABLE \`authorization_code\` CHANGE \`codeChallenge\` \`codeChallenge\` varchar(128) NULL`,
    );
    await queryRunner.query(
      `ALTER TABLE \`authorization_code\` CHANGE \`codeChallengeMethod\` \`codeChallengeMethod\` varchar(10) NULL`,
    );
    await queryRunner.query(
      `ALTER TABLE \`authorization_code\` CHANGE \`userId\` \`userId\` int NULL`,
    );
    await queryRunner.query(
      `ALTER TABLE \`authorization_code\` CHANGE \`clientId\` \`clientId\` int NULL`,
    );
    await queryRunner.query(
      `CREATE INDEX \`IDX_4970f47b75d7f9a7a05b21af4c\` ON \`token\` (\`clientId\`, \`userId\`)`,
    );
    await queryRunner.query(
      `CREATE INDEX \`IDX_95b8d1a91ad5a739f80fade352\` ON \`authorization_code\` (\`clientId\`, \`userId\`)`,
    );
    await queryRunner.query(
      `ALTER TABLE \`token\` ADD CONSTRAINT \`FK_94f168faad896c0786646fa3d4a\` FOREIGN KEY (\`userId\`) REFERENCES \`user\`(\`id\`) ON DELETE NO ACTION ON UPDATE NO ACTION`,
    );
    await queryRunner.query(
      `ALTER TABLE \`token\` ADD CONSTRAINT \`FK_8139f8b076cfd8723e992c9d9ff\` FOREIGN KEY (\`clientId\`) REFERENCES \`client\`(\`id\`) ON DELETE NO ACTION ON UPDATE NO ACTION`,
    );
    await queryRunner.query(
      `ALTER TABLE \`authorization_code\` ADD CONSTRAINT \`FK_c84c3d4d0e6344f36785f679e47\` FOREIGN KEY (\`userId\`) REFERENCES \`user\`(\`id\`) ON DELETE NO ACTION ON UPDATE NO ACTION`,
    );
    await queryRunner.query(
      `ALTER TABLE \`authorization_code\` ADD CONSTRAINT \`FK_ffbeadc85eea5dabbbcaf4f6b0e\` FOREIGN KEY (\`clientId\`) REFERENCES \`client\`(\`id\`) ON DELETE NO ACTION ON UPDATE NO ACTION`,
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `ALTER TABLE \`authorization_code\` DROP FOREIGN KEY \`FK_ffbeadc85eea5dabbbcaf4f6b0e\``,
    );
    await queryRunner.query(
      `ALTER TABLE \`authorization_code\` DROP FOREIGN KEY \`FK_c84c3d4d0e6344f36785f679e47\``,
    );
    await queryRunner.query(
      `ALTER TABLE \`token\` DROP FOREIGN KEY \`FK_8139f8b076cfd8723e992c9d9ff\``,
    );
    await queryRunner.query(
      `ALTER TABLE \`token\` DROP FOREIGN KEY \`FK_94f168faad896c0786646fa3d4a\``,
    );
    await queryRunner.query(
      `DROP INDEX \`IDX_95b8d1a91ad5a739f80fade352\` ON \`authorization_code\``,
    );
    await queryRunner.query(
      `DROP INDEX \`IDX_4970f47b75d7f9a7a05b21af4c\` ON \`token\``,
    );
    await queryRunner.query(
      `ALTER TABLE \`authorization_code\` CHANGE \`clientId\` \`clientId\` int NULL DEFAULT 'NULL'`,
    );
    await queryRunner.query(
      `ALTER TABLE \`authorization_code\` CHANGE \`userId\` \`userId\` int NULL DEFAULT 'NULL'`,
    );
    await queryRunner.query(
      `ALTER TABLE \`authorization_code\` CHANGE \`codeChallengeMethod\` \`codeChallengeMethod\` varchar(10) NULL DEFAULT 'NULL'`,
    );
    await queryRunner.query(
      `ALTER TABLE \`authorization_code\` CHANGE \`codeChallenge\` \`codeChallenge\` varchar(128) NULL DEFAULT 'NULL'`,
    );
    await queryRunner.query(
      `ALTER TABLE \`authorization_code\` CHANGE \`state\` \`state\` varchar(256) NULL DEFAULT 'NULL'`,
    );
    await queryRunner.query(
      `ALTER TABLE \`authorization_code\` DROP COLUMN \`scopes\``,
    );
    await queryRunner.query(
      `ALTER TABLE \`authorization_code\` ADD \`scopes\` longtext COLLATE "utf8mb4_bin" NULL DEFAULT 'NULL'`,
    );
    await queryRunner.query(
      `ALTER TABLE \`authorization_code\` CHANGE \`redirectUri\` \`redirectUri\` varchar(500) NULL DEFAULT 'NULL'`,
    );
    await queryRunner.query(
      `CREATE INDEX \`IDX_95b8d1a91ad5a739f80fade352\` ON \`authorization_code\` (\`clientId\`, \`userId\`)`,
    );
    await queryRunner.query(
      `ALTER TABLE \`authorization_code\` ADD CONSTRAINT \`FK_ffbeadc85eea5dabbbcaf4f6b0e\` FOREIGN KEY (\`clientId\`) REFERENCES \`client\`(\`id\`) ON DELETE NO ACTION ON UPDATE NO ACTION`,
    );
    await queryRunner.query(
      `ALTER TABLE \`authorization_code\` ADD CONSTRAINT \`FK_c84c3d4d0e6344f36785f679e47\` FOREIGN KEY (\`userId\`) REFERENCES \`user\`(\`id\`) ON DELETE NO ACTION ON UPDATE NO ACTION`,
    );
    await queryRunner.query(
      `ALTER TABLE \`token\` CHANGE \`clientId\` \`clientId\` int NULL DEFAULT 'NULL'`,
    );
    await queryRunner.query(
      `ALTER TABLE \`token\` CHANGE \`userId\` \`userId\` int NULL DEFAULT 'NULL'`,
    );
    await queryRunner.query(
      `ALTER TABLE \`token\` CHANGE \`revokedAt\` \`revokedAt\` datetime NULL DEFAULT 'NULL'`,
    );
    await queryRunner.query(`ALTER TABLE \`token\` DROP COLUMN \`scopes\``);
    await queryRunner.query(
      `ALTER TABLE \`token\` ADD \`scopes\` longtext COLLATE "utf8mb4_bin" NULL DEFAULT 'NULL'`,
    );
    await queryRunner.query(
      `ALTER TABLE \`token\` CHANGE \`refreshExpiresAt\` \`refreshExpiresAt\` datetime NULL DEFAULT 'NULL'`,
    );
    await queryRunner.query(
      `ALTER TABLE \`token\` CHANGE \`refreshToken\` \`refreshToken\` varchar(2048) NULL DEFAULT 'NULL'`,
    );
    await queryRunner.query(
      `CREATE INDEX \`IDX_4970f47b75d7f9a7a05b21af4c\` ON \`token\` (\`clientId\`, \`userId\`)`,
    );
    await queryRunner.query(
      `ALTER TABLE \`token\` ADD CONSTRAINT \`FK_8139f8b076cfd8723e992c9d9ff\` FOREIGN KEY (\`clientId\`) REFERENCES \`client\`(\`id\`) ON DELETE NO ACTION ON UPDATE NO ACTION`,
    );
    await queryRunner.query(
      `ALTER TABLE \`token\` ADD CONSTRAINT \`FK_94f168faad896c0786646fa3d4a\` FOREIGN KEY (\`userId\`) REFERENCES \`user\`(\`id\`) ON DELETE NO ACTION ON UPDATE NO ACTION`,
    );
    await queryRunner.query(
      `ALTER TABLE \`client\` CHANGE \`policyUri\` \`policyUri\` varchar(500) NULL DEFAULT 'NULL'`,
    );
    await queryRunner.query(
      `ALTER TABLE \`client\` CHANGE \`termsOfServiceUri\` \`termsOfServiceUri\` varchar(500) NULL DEFAULT 'NULL'`,
    );
    await queryRunner.query(
      `ALTER TABLE \`client\` CHANGE \`logoUri\` \`logoUri\` varchar(500) NULL DEFAULT 'NULL'`,
    );
    await queryRunner.query(
      `ALTER TABLE \`client\` CHANGE \`description\` \`description\` varchar(500) NULL DEFAULT 'NULL'`,
    );
    await queryRunner.query(`ALTER TABLE \`client\` DROP COLUMN \`scopes\``);
    await queryRunner.query(
      `ALTER TABLE \`client\` ADD \`scopes\` longtext COLLATE "utf8mb4_bin" NULL DEFAULT 'NULL'`,
    );
    await queryRunner.query(
      `ALTER TABLE \`client\` CHANGE \`clientSecret\` \`clientSecret\` varchar(255) NULL DEFAULT 'NULL'`,
    );
    await queryRunner.query(
      `ALTER TABLE \`user\` CHANGE \`location\` \`location\` varchar(255) NULL DEFAULT 'NULL'`,
    );
    await queryRunner.query(
      `ALTER TABLE \`user\` CHANGE \`website\` \`website\` varchar(255) NULL DEFAULT 'NULL'`,
    );
    await queryRunner.query(
      `ALTER TABLE \`user\` CHANGE \`bio\` \`bio\` text NULL DEFAULT 'NULL'`,
    );
    await queryRunner.query(
      `ALTER TABLE \`user\` CHANGE \`avatar\` \`avatar\` varchar(500) NULL DEFAULT 'NULL'`,
    );
    await queryRunner.query(`ALTER TABLE \`user\` DROP COLUMN \`backupCodes\``);
    await queryRunner.query(
      `ALTER TABLE \`user\` ADD \`backupCodes\` longtext COLLATE "utf8mb4_bin" NULL DEFAULT 'NULL'`,
    );
    await queryRunner.query(
      `ALTER TABLE \`user\` CHANGE \`twoFactorSecret\` \`twoFactorSecret\` varchar(255) NULL DEFAULT 'NULL'`,
    );
    await queryRunner.query(
      `ALTER TABLE \`user\` CHANGE \`lastLoginAt\` \`lastLoginAt\` datetime NULL DEFAULT 'NULL'`,
    );
    await queryRunner.query(
      `ALTER TABLE \`user\` CHANGE \`lastName\` \`lastName\` varchar(100) NULL DEFAULT 'NULL'`,
    );
    await queryRunner.query(
      `ALTER TABLE \`user\` CHANGE \`firstName\` \`firstName\` varchar(100) NULL DEFAULT 'NULL'`,
    );
  }
}
