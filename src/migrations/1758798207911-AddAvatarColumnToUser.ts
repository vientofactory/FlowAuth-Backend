import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddAvatarColumnToUser1758798207911 implements MigrationInterface {
  name = 'AddAvatarColumnToUser1758798207911';

  public async up(queryRunner: QueryRunner): Promise<void> {
    // Check if avatar column already exists
    const columnExists = await queryRunner.hasColumn('user', 'avatar');

    if (!columnExists) {
      // Add avatar column to user table
      await queryRunner.query(`
        ALTER TABLE \`user\`
        ADD COLUMN \`avatar\` varchar(500) NULL
      `);
    }
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    // Check if avatar column exists before dropping
    const columnExists = await queryRunner.hasColumn('user', 'avatar');

    if (columnExists) {
      // Drop avatar column from user table
      await queryRunner.query(`
        ALTER TABLE \`user\`
        DROP COLUMN \`avatar\`
      `);
    }
  }
}
