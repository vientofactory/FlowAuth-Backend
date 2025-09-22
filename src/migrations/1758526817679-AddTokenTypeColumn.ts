import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddTokenTypeColumn1758526817679 implements MigrationInterface {
  name = 'AddTokenTypeColumn1758526817679';

  public async up(queryRunner: QueryRunner): Promise<void> {
    // Add tokenType column to token table
    await queryRunner.query(`
      ALTER TABLE \`token\`
      ADD COLUMN \`tokenType\` varchar(20) NOT NULL DEFAULT 'login'
    `);

    // Update existing tokens: if clientId is not null, set to 'oauth2', otherwise keep 'login'
    await queryRunner.query(`
      UPDATE \`token\`
      SET \`tokenType\` = CASE
        WHEN \`clientId\` IS NOT NULL THEN 'oauth2'
        ELSE 'login'
      END
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    // Drop tokenType column
    await queryRunner.query(`
      ALTER TABLE \`token\`
      DROP COLUMN \`tokenType\`
    `);
  }
}
