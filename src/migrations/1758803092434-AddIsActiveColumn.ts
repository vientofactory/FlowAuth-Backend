import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddIsActiveColumn1758803092434 implements MigrationInterface {
  name = 'AddIsActiveColumn1758803092434';

  public async up(queryRunner: QueryRunner): Promise<void> {
    // Check if isActive column already exists
    const columnExists = await queryRunner.hasColumn('user', 'isActive');

    if (!columnExists) {
      // Add isActive column to user table
      await queryRunner.query(`
        ALTER TABLE \`user\`
        ADD COLUMN \`isActive\` tinyint NOT NULL DEFAULT 1
      `);
    }
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    // Check if isActive column exists before dropping
    const columnExists = await queryRunner.hasColumn('user', 'isActive');

    if (columnExists) {
      // Drop isActive column from user table
      await queryRunner.query(`
        ALTER TABLE \`user\`
        DROP COLUMN \`isActive\`
      `);
    }
  }
}
