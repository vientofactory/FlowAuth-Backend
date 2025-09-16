-- 권한 시스템 마이그레이션
-- 기존 roles 컬럼을 permissions 컬럼으로 변경

-- 1. permissions 컬럼 추가
ALTER TABLE `user` ADD COLUMN `permissions` BIGINT DEFAULT 1;

-- 2. 기존 사용자들의 권한을 기본 권한(READ_USER = 1)으로 설정
UPDATE `user` SET `permissions` = 1 WHERE `permissions` IS NULL;

-- 3. roles 컬럼 삭제 (기존 데이터는 이미 백업됨)
ALTER TABLE `user` DROP COLUMN `roles`;