import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddUserIdToClient1758117590059 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    // Check if userId column already exists
    const userIdColumn = await queryRunner.hasColumn('client', 'userId');
    if (!userIdColumn) {
      // Client 테이블에 userId 컬럼 추가
      await queryRunner.query(`
              ALTER TABLE client
              ADD COLUMN userId int NOT NULL
          `);
    }

    // Check if foreign key constraint already exists
    const foreignKeys = await queryRunner.query(`
      SELECT CONSTRAINT_NAME FROM INFORMATION_SCHEMA.TABLE_CONSTRAINTS 
      WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'client' 
      AND CONSTRAINT_NAME = 'FK_client_user'
    `);

    if (foreignKeys.length === 0) {
      // 외래 키 제약조건 추가
      await queryRunner.query(`
              ALTER TABLE client
              ADD CONSTRAINT FK_client_user
              FOREIGN KEY (userId) REFERENCES user(id) ON DELETE CASCADE
          `);
    }
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    // Check if foreign key constraint exists before dropping
    const foreignKeys = await queryRunner.query(`
      SELECT CONSTRAINT_NAME FROM INFORMATION_SCHEMA.TABLE_CONSTRAINTS 
      WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'client' 
      AND CONSTRAINT_NAME = 'FK_client_user'
    `);

    if (foreignKeys && foreignKeys.length > 0) {
      // 외래 키 제약조건 제거
      await queryRunner.query(`
              ALTER TABLE client
              DROP FOREIGN KEY FK_client_user
          `);
    }

    // Check if userId column exists before dropping
    const userIdColumn = await queryRunner.hasColumn('client', 'userId');
    if (userIdColumn) {
      // userId 컬럼 제거
      await queryRunner.query(`
              ALTER TABLE client
              DROP COLUMN userId
          `);
    }
  }
}
