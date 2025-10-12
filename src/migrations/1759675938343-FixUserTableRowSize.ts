import { MigrationInterface, QueryRunner } from 'typeorm';

export class FixUserTableRowSize1759675938343 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    // Fix row size issue by converting large varchar columns to TEXT
    await queryRunner.query(
      `ALTER TABLE \`user\` MODIFY COLUMN \`avatar\` TEXT NULL`,
    );
    await queryRunner.query(
      `ALTER TABLE \`user\` MODIFY COLUMN \`website\` TEXT NULL`,
    );
    await queryRunner.query(
      `ALTER TABLE \`user\` MODIFY COLUMN \`location\` TEXT NULL`,
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    // Revert TEXT columns back to VARCHAR
    await queryRunner.query(
      `ALTER TABLE \`user\` MODIFY COLUMN \`avatar\` VARCHAR(500) NULL`,
    );
    await queryRunner.query(
      `ALTER TABLE \`user\` MODIFY COLUMN \`website\` VARCHAR(255) NULL`,
    );
    await queryRunner.query(
      `ALTER TABLE \`user\` MODIFY COLUMN \`location\` VARCHAR(255) NULL`,
    );
  }
}
