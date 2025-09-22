import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddUserTypeAndTwoFactorColumns1758259000000
  implements MigrationInterface
{
  name = 'AddUserTypeAndTwoFactorColumns1758259000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    // userType 컬럼이 이미 존재하는 경우를 확인
    const hasUserTypeColumn = await queryRunner.hasColumn('user', 'userType');
    const hasTwoFactorSecretColumn = await queryRunner.hasColumn(
      'user',
      'twoFactorSecret',
    );
    const hasIsTwoFactorEnabledColumn = await queryRunner.hasColumn(
      'user',
      'isTwoFactorEnabled',
    );
    const hasBackupCodesColumn = await queryRunner.hasColumn(
      'user',
      'backupCodes',
    );

    if (!hasUserTypeColumn) {
      await queryRunner.query(`
        ALTER TABLE \`user\`
        ADD \`userType\` varchar(20) NOT NULL DEFAULT 'regular'
      `);
    }

    if (!hasTwoFactorSecretColumn) {
      await queryRunner.query(`
        ALTER TABLE \`user\`
        ADD \`twoFactorSecret\` varchar(255) NULL
      `);
    }

    if (!hasIsTwoFactorEnabledColumn) {
      await queryRunner.query(`
        ALTER TABLE \`user\`
        ADD \`isTwoFactorEnabled\` tinyint NOT NULL DEFAULT 0
      `);
    }

    if (!hasBackupCodesColumn) {
      await queryRunner.query(`
        ALTER TABLE \`user\`
        ADD \`backupCodes\` json NULL
      `);
    }
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      ALTER TABLE \`user\`
      DROP COLUMN \`backupCodes\`
    `);

    await queryRunner.query(`
      ALTER TABLE \`user\`
      DROP COLUMN \`isTwoFactorEnabled\`
    `);

    await queryRunner.query(`
      ALTER TABLE \`user\`
      DROP COLUMN \`twoFactorSecret\`
    `);

    await queryRunner.query(`
      ALTER TABLE \`user\`
      DROP COLUMN \`userType\`
    `);
  }
}
