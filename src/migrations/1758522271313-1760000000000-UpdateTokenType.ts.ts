import { MigrationInterface, QueryRunner } from 'typeorm';

export class UpdateTokenType1758522271313 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    // Update existing tokens: if client_id is not null, set to 'oauth2', otherwise 'login'
    await queryRunner.query(`
      UPDATE token
      SET tokenType = CASE
        WHEN clientId IS NOT NULL THEN 'oauth2'
        ELSE 'login'
      END
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    // Revert to default 'bearer'
    await queryRunner.query(`
      UPDATE token
      SET tokenType = 'bearer'
    `);
  }
}
