import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddLastLoginAtToUser1758257376000 implements MigrationInterface {
  name = 'AddLastLoginAtToUser1758257376000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      ALTER TABLE \`user\`
      ADD \`lastLoginAt\` datetime NULL
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      ALTER TABLE \`user\`
      DROP COLUMN \`lastLoginAt\`
    `);
  }
}
