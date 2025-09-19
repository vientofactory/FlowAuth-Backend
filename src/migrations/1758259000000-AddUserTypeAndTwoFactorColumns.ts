import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddUserTypeAndTwoFactorColumns1758259000000
  implements MigrationInterface
{
  name = 'AddUserTypeAndTwoFactorColumns1758259000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      ALTER TABLE \`user\`
      ADD \`userType\` varchar(20) NOT NULL DEFAULT 'regular'
    `);

    await queryRunner.query(`
      ALTER TABLE \`user\`
      ADD \`twoFactorSecret\` varchar(255) NULL
    `);

    await queryRunner.query(`
      ALTER TABLE \`user\`
      ADD \`isTwoFactorEnabled\` tinyint NOT NULL DEFAULT 0
    `);

    await queryRunner.query(`
      ALTER TABLE \`user\`
      ADD \`backupCodes\` json NULL
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      ALTER TABLE \`user\`
      DROP COLUMN \`backupCodes\`
    `);

    await queryRunner.query(`
      ALTER TABLE \`user\`
      DROP COLUMN \`isTwoFactorEnabled\`
    `);

    await queryRunner.query(`
      ALTER TABLE \`user\`
      DROP COLUMN \`twoFactorSecret\`
    `);

    await queryRunner.query(`
      ALTER TABLE \`user\`
      DROP COLUMN \`userType\`
    `);
  }
}
