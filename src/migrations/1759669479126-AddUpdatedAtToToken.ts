import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddUpdatedAtToToken1759669479126 implements MigrationInterface {
  name = 'AddUpdatedAtToToken1759669479126';

  public async up(queryRunner: QueryRunner): Promise<void> {
    // Check if updatedAt column already exists
    const table = await queryRunner.getTable('token');
    const updatedAtColumn = table?.findColumnByName('updatedAt');

    if (!updatedAtColumn) {
      await queryRunner.query(
        `ALTER TABLE \`token\` ADD \`updatedAt\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6)`,
      );
    }
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`ALTER TABLE \`token\` DROP COLUMN \`updatedAt\``);
  }
}
