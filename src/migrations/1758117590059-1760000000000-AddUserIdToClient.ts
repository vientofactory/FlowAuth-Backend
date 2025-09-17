import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddUserIdToClient1758117590059 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    // Client 테이블에 userId 컬럼 추가
    await queryRunner.query(`
            ALTER TABLE client
            ADD COLUMN userId int NOT NULL
        `);

    // 외래 키 제약조건 추가
    await queryRunner.query(`
            ALTER TABLE client
            ADD CONSTRAINT FK_client_user
            FOREIGN KEY (userId) REFERENCES user(id) ON DELETE CASCADE
        `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    // 외래 키 제약조건 제거
    await queryRunner.query(`
            ALTER TABLE client
            DROP FOREIGN KEY FK_client_user
        `);

    // userId 컬럼 제거
    await queryRunner.query(`
            ALTER TABLE client
            DROP COLUMN userId
        `);
  }
}
