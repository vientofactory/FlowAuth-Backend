import { MigrationInterface, QueryRunner } from 'typeorm';

export class UpdateClientForeignKeys1760000000001
  implements MigrationInterface
{
  public async up(queryRunner: QueryRunner): Promise<void> {
    // Update token table foreign key to CASCADE DELETE
    // Get all FK constraints that reference the client table
    const tokenClientConstraints = (await queryRunner.query(`
      SELECT CONSTRAINT_NAME
      FROM INFORMATION_SCHEMA.KEY_COLUMN_USAGE
      WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'token'
      AND REFERENCED_TABLE_NAME = 'client'
    `)) as Array<{ CONSTRAINT_NAME: string }>;

    if (tokenClientConstraints.length > 0) {
      const tokenClientFk = tokenClientConstraints[0];

      // Drop existing foreign key
      await queryRunner.query(`
        ALTER TABLE token DROP FOREIGN KEY \`${tokenClientFk.CONSTRAINT_NAME}\`
      `);

      // Recreate with CASCADE DELETE
      await queryRunner.query(`
        ALTER TABLE token
        ADD CONSTRAINT FK_token_client
        FOREIGN KEY (clientId) REFERENCES client(id) ON DELETE CASCADE
      `);
    }

    // Update authorization_code table foreign key to CASCADE DELETE
    const authCodeClientConstraints = (await queryRunner.query(`
      SELECT CONSTRAINT_NAME
      FROM INFORMATION_SCHEMA.KEY_COLUMN_USAGE
      WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'authorization_code'
      AND REFERENCED_TABLE_NAME = 'client'
    `)) as Array<{ CONSTRAINT_NAME: string }>;

    if (authCodeClientConstraints.length > 0) {
      const authCodeClientFk = authCodeClientConstraints[0];

      // Drop existing foreign key
      await queryRunner.query(`
        ALTER TABLE authorization_code DROP FOREIGN KEY \`${authCodeClientFk.CONSTRAINT_NAME}\`
      `);

      // Recreate with CASCADE DELETE
      await queryRunner.query(`
        ALTER TABLE authorization_code
        ADD CONSTRAINT FK_authorization_code_client
        FOREIGN KEY (clientId) REFERENCES client(id) ON DELETE CASCADE
      `);
    }
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    // Revert token table foreign key to NO ACTION
    const tokenForeignKeys = (await queryRunner.query(`
      SELECT CONSTRAINT_NAME
      FROM INFORMATION_SCHEMA.TABLE_CONSTRAINTS
      WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'token'
      AND CONSTRAINT_NAME = 'FK_token_client'
    `)) as Array<{ CONSTRAINT_NAME: string }>;

    if (tokenForeignKeys.length > 0) {
      await queryRunner.query(`
        ALTER TABLE token DROP FOREIGN KEY FK_token_client
      `);

      // Recreate with NO ACTION
      await queryRunner.query(`
        ALTER TABLE token
        ADD CONSTRAINT FK_token_client
        FOREIGN KEY (clientId) REFERENCES client(id) ON DELETE NO ACTION ON UPDATE NO ACTION
      `);
    }

    // Revert authorization_code table foreign key to NO ACTION
    const authCodeForeignKeys = (await queryRunner.query(`
      SELECT CONSTRAINT_NAME
      FROM INFORMATION_SCHEMA.TABLE_CONSTRAINTS
      WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'authorization_code'
      AND CONSTRAINT_NAME = 'FK_authorization_code_client'
    `)) as Array<{ CONSTRAINT_NAME: string }>;

    if (authCodeForeignKeys.length > 0) {
      await queryRunner.query(`
        ALTER TABLE authorization_code DROP FOREIGN KEY FK_authorization_code_client
      `);

      // Recreate with NO ACTION
      await queryRunner.query(`
        ALTER TABLE authorization_code
        ADD CONSTRAINT FK_authorization_code_client
        FOREIGN KEY (clientId) REFERENCES client(id) ON DELETE NO ACTION ON UPDATE NO ACTION
      `);
    }
  }
}
