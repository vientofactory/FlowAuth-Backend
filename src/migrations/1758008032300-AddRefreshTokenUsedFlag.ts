import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddRefreshTokenUsedFlag1758008032300
  implements MigrationInterface
{
  name = 'AddRefreshTokenUsedFlag1758008032300';

  public async up(queryRunner: QueryRunner): Promise<void> {
    // Check if column already exists
    const column = await queryRunner.hasColumn('token', 'isRefreshTokenUsed');
    if (!column) {
      await queryRunner.query(`
        ALTER TABLE \`token\`
        ADD COLUMN \`isRefreshTokenUsed\` TINYINT(1) DEFAULT 0
      `);
    }
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    // Check if column exists before dropping
    const column = await queryRunner.hasColumn('token', 'isRefreshTokenUsed');
    if (column) {
      await queryRunner.query(`
        ALTER TABLE \`token\`
        DROP COLUMN \`isRefreshTokenUsed\`
      `);
    }
  }
}
