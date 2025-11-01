import { DataSource } from 'typeorm';
import * as dotenv from 'dotenv';

dotenv.config();

export default new DataSource({
  type: 'mysql',
  host: process.env.DB_HOST ?? 'localhost',
  port: parseInt(process.env.DB_PORT ?? '3306', 10),
  username: process.env.DB_USERNAME ?? 'root',
  password: process.env.DB_PASSWORD ?? '',
  database: process.env.DB_NAME ?? 'flowauth',
  entities: ['src/**/*.entity{.ts,.js}'],
  migrations: ['src/migrations/*{.ts,.js}'],
  synchronize: false, // 프로덕션에서는 false
  dropSchema: false, // 스키마 드롭 비활성화
  migrationsRun: false, // 자동 마이그레이션 실행 비활성화
  logging: process.env.NODE_ENV === 'development',
  // 추가 설정으로 스키마 자동 검사를 비활성화
  extra: {
    connectionLimit: parseInt(process.env.DB_CONNECTION_LIMIT ?? '10', 10),
    // TypeORM이 스키마를 자동으로 검사하지 않도록 설정
    acquireTimeout: 60000,
    timeout: 60000,
  },
});
