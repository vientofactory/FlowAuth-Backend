import { MigrationInterface, QueryRunner } from 'typeorm';

export class UpdateUserPermissions1758043742996 implements MigrationInterface {
  name = 'UpdateUserPermissions1758043742996';

  public async up(queryRunner: QueryRunner): Promise<void> {
    // Check if permissions column already exists
    const permissionsColumn = await queryRunner.hasColumn(
      'user',
      'permissions',
    );
    if (!permissionsColumn) {
      // 기존 roles 데이터를 백업
      await queryRunner.query(`
        ALTER TABLE \`user\` ADD COLUMN \`permissions\` BIGINT DEFAULT 1
      `);
    }

    // 기존 사용자들의 권한을 기본 권한(READ_USER = 1)으로 설정
    await queryRunner.query(`
      UPDATE \`user\` SET \`permissions\` = 1 WHERE \`permissions\` IS NULL
    `);

    // Check if roles column exists before dropping
    const rolesColumn = await queryRunner.hasColumn('user', 'roles');
    if (rolesColumn) {
      // roles 컬럼 삭제
      await queryRunner.query(`
        ALTER TABLE \`user\` DROP COLUMN \`roles\`
      `);
    }
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    // Check if roles column exists before adding
    const rolesColumn = await queryRunner.hasColumn('user', 'roles');
    if (!rolesColumn) {
      // roles 컬럼 다시 추가
      await queryRunner.query(`
        ALTER TABLE \`user\` ADD COLUMN \`roles\` JSON NULL
      `);
    }

    // 기본 roles 설정
    await queryRunner.query(`
      UPDATE \`user\` SET \`roles\` = JSON_ARRAY('user') WHERE \`roles\` IS NULL
    `);

    // Check if permissions column exists before dropping
    const permissionsColumn = await queryRunner.hasColumn(
      'user',
      'permissions',
    );
    if (permissionsColumn) {
      // permissions 컬럼 삭제
      await queryRunner.query(`
        ALTER TABLE \`user\` DROP COLUMN \`permissions\`
      `);
    }
  }
}
