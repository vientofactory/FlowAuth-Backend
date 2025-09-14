import { MigrationInterface, QueryRunner } from 'typeorm';

export class UpdateTokenColumns1694735885000 implements MigrationInterface {
  name = 'UpdateTokenColumns1694735885000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    // Update accessToken column to TEXT type
    await queryRunner.query(
      `ALTER TABLE \`token\` MODIFY COLUMN \`accessToken\` TEXT NOT NULL`,
    );

    // Update refreshToken column to TEXT type
    await queryRunner.query(
      `ALTER TABLE \`token\` MODIFY COLUMN \`refreshToken\` TEXT NULL`,
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    // Revert accessToken column to VARCHAR(255)
    await queryRunner.query(
      `ALTER TABLE \`token\` MODIFY COLUMN \`accessToken\` VARCHAR(255) NOT NULL`,
    );

    // Revert refreshToken column to VARCHAR(255)
    await queryRunner.query(
      `ALTER TABLE \`token\` MODIFY COLUMN \`refreshToken\` VARCHAR(255) NULL`,
    );
  }
}
