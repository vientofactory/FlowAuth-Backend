import { MigrationInterface, QueryRunner } from 'typeorm';

export class UpdateUserPermissions1758043742996 implements MigrationInterface {
  name = 'UpdateUserPermissions1758043742996';

  public async up(queryRunner: QueryRunner): Promise<void> {
    // 기존 roles 데이터를 백업
    await queryRunner.query(`
      ALTER TABLE \`user\` ADD COLUMN \`permissions\` BIGINT DEFAULT 1
    `);

    // 기존 사용자들의 권한을 기본 권한(READ_USER = 1)으로 설정
    await queryRunner.query(`
      UPDATE \`user\` SET \`permissions\` = 1 WHERE \`permissions\` IS NULL
    `);

    // roles 컬럼 삭제
    await queryRunner.query(`
      ALTER TABLE \`user\` DROP COLUMN \`roles\`
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    // roles 컬럼 다시 추가
    await queryRunner.query(`
      ALTER TABLE \`user\` ADD COLUMN \`roles\` JSON NULL
    `);

    // 기본 roles 설정
    await queryRunner.query(`
      UPDATE \`user\` SET \`roles\` = JSON_ARRAY('user') WHERE \`roles\` IS NULL
    `);

    // permissions 컬럼 삭제
    await queryRunner.query(`
      ALTER TABLE \`user\` DROP COLUMN \`permissions\`
    `);
  }
}
