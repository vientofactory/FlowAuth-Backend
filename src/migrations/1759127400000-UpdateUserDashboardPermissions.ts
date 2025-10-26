import { MigrationInterface, QueryRunner } from 'typeorm';

export class UpdateUserDashboardPermissions1759127400000
  implements MigrationInterface
{
  name = 'UpdateUserDashboardPermissions1759127400000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    // READ_DASHBOARD (2048), WRITE_DASHBOARD (4096), UPLOAD_FILE (16384) 권한 추가
    // 기존 사용자들에게 대시보드 권한 부여

    // 일반 사용자 (userType = 'regular')에게 기본 권한 + 대시보드 + 업로드 권한 부여
    // READ_USER (1) | READ_DASHBOARD (2048) | WRITE_DASHBOARD (4096) | UPLOAD_FILE (16384) = 22529
    await queryRunner.query(`
      UPDATE \`user\` 
      SET \`permissions\` = \`permissions\` | 22528
      WHERE \`userType\` = 'regular' AND \`permissions\` & 2048 = 0
    `);

    // 개발자 사용자 (userType = 'developer')에게 추가 권한 부여
    // 기존 권한에 READ_DASHBOARD (2048) | WRITE_DASHBOARD (4096) | UPLOAD_FILE (16384) = 22528 추가
    await queryRunner.query(`
      UPDATE \`user\` 
      SET \`permissions\` = \`permissions\` | 22528
      WHERE \`userType\` = 'developer' AND \`permissions\` & 2048 = 0
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    // READ_DASHBOARD (2048), WRITE_DASHBOARD (4096), UPLOAD_FILE (16384) 권한 제거
    // 22528 = 2048 + 4096 + 16384
    await queryRunner.query(`
      UPDATE \`user\` 
      SET \`permissions\` = \`permissions\` & ~22528
      WHERE \`permissions\` & 22528 != 0
    `);
  }
}
