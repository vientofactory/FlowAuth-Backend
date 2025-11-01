import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddResponseTypeToAuthorizationCode1761393140432
  implements MigrationInterface
{
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `ALTER TABLE authorization_code ADD COLUMN responseType varchar(50) NULL`,
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `ALTER TABLE authorization_code DROP COLUMN responseType`,
    );
  }
}
