-- Migration: Add Snowflake ID to User table
-- Description: User 테이블에 userId 컬럼 추가 (로그인 시 동적 생성)
-- Date: 2025-11-05

USE flowauth;

-- 1. userId 컬럼 추가 (nullable - 로그인 시 생성됨)
ALTER TABLE `user` ADD COLUMN `userId` VARCHAR(255) NULL 
COMMENT 'Snowflake ID for user identification - generated on first login';

-- 2. userId 컬럼에 대한 unique 인덱스 추가 (NULL 값 허용)
ALTER TABLE `user` ADD UNIQUE INDEX `IDX_user_userId` (`userId`);

-- 3. 검증: 테이블 구조 확인
DESCRIBE `user`;

-- 롤백을 위한 명령어 (필요시 사용)
-- ALTER TABLE `user` DROP INDEX `IDX_user_userId`;
-- ALTER TABLE `user` DROP COLUMN `userId`;