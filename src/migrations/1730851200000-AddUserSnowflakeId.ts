import {
  MigrationInterface,
  QueryRunner,
  TableColumn,
  TableIndex,
} from 'typeorm';

export class AddUserSnowflakeId1730851200000 implements MigrationInterface {
  name = 'AddUserSnowflakeId1730851200000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    // userId 컬럼 추가 (nullable로 추가 - 로그인 시 동적 생성)
    await queryRunner.addColumn(
      'user',
      new TableColumn({
        name: 'userId',
        type: 'varchar',
        length: '255',
        isNullable: true,
        comment:
          'Snowflake ID for user identification - generated on first login',
      }),
    );

    // 고유 인덱스 추가 (NULL 값 허용)
    await queryRunner.createIndex(
      'user',
      new TableIndex({
        name: 'IDX_user_userId',
        columnNames: ['userId'],
        isUnique: true,
      }),
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    // 1. 인덱스 제거
    await queryRunner.dropIndex('user', 'IDX_user_userId');

    // 2. 컬럼 제거
    await queryRunner.dropColumn('user', 'userId');
  }
}
