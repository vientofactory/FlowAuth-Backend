import { MigrationInterface, QueryRunner } from 'typeorm';

export class FixClientUserForeignKey1758258451325
  implements MigrationInterface
{
  public async up(queryRunner: QueryRunner): Promise<void> {
    // 실제 존재하는 외래 키 제약조건 이름 확인
    const foreignKeys = (await queryRunner.query(`
      SELECT CONSTRAINT_NAME
      FROM INFORMATION_SCHEMA.TABLE_CONSTRAINTS
      WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'client'
      AND CONSTRAINT_TYPE = 'FOREIGN KEY'
    `)) as Array<{ CONSTRAINT_NAME: string }>;

    // TypeORM이 자동 생성한 외래 키 제약조건이 존재하는 경우
    const typeormFk = foreignKeys.find((fk) =>
      fk.CONSTRAINT_NAME.startsWith('FK_'),
    );

    if (typeormFk) {
      // 기존 제약조건을 삭제하고 새 이름으로 다시 생성
      await queryRunner.query(`
        ALTER TABLE client DROP FOREIGN KEY \`${typeormFk.CONSTRAINT_NAME}\`
      `);

      // 새 이름으로 외래 키 제약조건 생성
      await queryRunner.query(`
        ALTER TABLE client
        ADD CONSTRAINT FK_client_user
        FOREIGN KEY (userId) REFERENCES user(id) ON DELETE CASCADE
      `);
    } else {
      // 제약조건이 없는 경우 새로 생성
      await queryRunner.query(`
        ALTER TABLE client
        ADD CONSTRAINT FK_client_user
        FOREIGN KEY (userId) REFERENCES user(id) ON DELETE CASCADE
      `);
    }
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    // Drop the foreign key constraint
    const foreignKeys = (await queryRunner.query(`
      SELECT CONSTRAINT_NAME
      FROM INFORMATION_SCHEMA.TABLE_CONSTRAINTS
      WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'client'
      AND CONSTRAINT_NAME = 'FK_client_user'
    `)) as Array<{ CONSTRAINT_NAME: string }>;

    if (foreignKeys.length > 0) {
      await queryRunner.query(`
        ALTER TABLE client DROP FOREIGN KEY FK_client_user
      `);
    }

    // Also drop any associated indexes that might have been created
    const indexes = (await queryRunner.query(`
      SELECT INDEX_NAME
      FROM INFORMATION_SCHEMA.STATISTICS
      WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'client'
      AND COLUMN_NAME = 'userId'
      AND INDEX_NAME != 'PRIMARY'
    `)) as Array<{ INDEX_NAME: string }>;

    for (const index of indexes) {
      try {
        await queryRunner.query(`
          ALTER TABLE client DROP INDEX \`${index.INDEX_NAME}\`
        `);
      } catch (error) {
        // Ignore errors if index doesn't exist or is needed by other constraints
        console.log(
          'Could not drop index %s:',
          index.INDEX_NAME,
          String(error),
        );
      }
    }
  }
}
