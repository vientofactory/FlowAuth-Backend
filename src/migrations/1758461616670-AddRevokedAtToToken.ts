import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddRevokedAtToToken1758461616670 implements MigrationInterface {
  name = 'AddRevokedAtToToken1758461616670';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `ALTER TABLE \`token\` ADD \`revokedAt\` datetime NULL`,
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`ALTER TABLE \`token\` DROP COLUMN \`revokedAt\``);
  }
}
