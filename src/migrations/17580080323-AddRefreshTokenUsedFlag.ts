import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddRefreshTokenUsedFlag17580080323 implements MigrationInterface {
  name = 'AddRefreshTokenUsedFlag17580080323';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      ALTER TABLE \`token\`
      ADD COLUMN \`isRefreshTokenUsed\` TINYINT(1) DEFAULT 0
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      ALTER TABLE \`token\`
      DROP COLUMN \`isRefreshTokenUsed\`
    `);
  }
}
