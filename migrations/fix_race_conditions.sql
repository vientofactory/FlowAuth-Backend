-- Race Condition 방지를 위한 데이터베이스 제약조건 및 인덱스 개선

-- 데이터베이스 선택
USE flowauth;

-- Start transaction for safety
START TRANSACTION;

-- Temporarily disable foreign key checks to avoid constraint issues
SET FOREIGN_KEY_CHECKS = 0;

-- 1. User 테이블 개선
-- username과 email에 유니크 제약조건 추가 (이미 있다면 에러 무시)
CREATE UNIQUE INDEX IF NOT EXISTS `IDX_user_username` ON `user` (`username`);
CREATE UNIQUE INDEX IF NOT EXISTS `IDX_user_email` ON `user` (`email`);

-- 성능 최적화를 위한 복합 인덱스 추가
CREATE INDEX IF NOT EXISTS `IDX_user_id_isActive` ON `user` (`id`, `isActive`);

-- 2. Token 테이블 개선
-- 토큰 사용 추적을 위한 컬럼 추가 (존재하지 않을 경우에만)
SET @col_exists_lastUsedAt = (
    SELECT COUNT(1) 
    FROM INFORMATION_SCHEMA.COLUMNS 
    WHERE TABLE_SCHEMA = 'flowauth' 
    AND TABLE_NAME = 'token' 
    AND COLUMN_NAME = 'lastUsedAt'
);

SET @sql = IF(@col_exists_lastUsedAt = 0, 
    'ALTER TABLE `token` ADD COLUMN `lastUsedAt` DATETIME NULL AFTER `rotationGeneration`', 
    'SELECT "Column lastUsedAt already exists"'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @col_exists_lastUsedIp = (
    SELECT COUNT(1) 
    FROM INFORMATION_SCHEMA.COLUMNS 
    WHERE TABLE_SCHEMA = 'flowauth' 
    AND TABLE_NAME = 'token' 
    AND COLUMN_NAME = 'lastUsedIp'
);

SET @sql = IF(@col_exists_lastUsedIp = 0, 
    'ALTER TABLE `token` ADD COLUMN `lastUsedIp` VARCHAR(45) NULL AFTER `lastUsedAt`', 
    'SELECT "Column lastUsedIp already exists"'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- 토큰 패밀리-세대 유니크 제약조건 추가
CREATE UNIQUE INDEX IF NOT EXISTS `IDX_token_family_generation` ON `token` (`tokenFamily`, `rotationGeneration`);

-- 토큰 사용 시간 추적 인덱스
CREATE INDEX IF NOT EXISTS `IDX_token_lastUsed` ON `token` (`lastUsedAt`);

-- 3. Client 테이블 개선
-- clientId 유니크 제약조건 추가
CREATE UNIQUE INDEX IF NOT EXISTS `IDX_client_clientId` ON `client` (`clientId`);

-- Drop any conflicting indexes safely
DROP INDEX IF EXISTS `IDX_4970f47b75d7f9a7a05b21af4c` ON `token`;
DROP INDEX IF EXISTS `IDX_token_user_client` ON `token`;

-- 4. Token 테이블 성능 최적화 인덱스들 (안전하게 생성)
-- 토큰 만료 시간 기반 조회 최적화
CREATE INDEX IF NOT EXISTS `IDX_token_expires` ON `token` (`expiresAt`, `isRevoked`);

-- 리프레시 토큰 만료 시간 기반 조회 최적화
CREATE INDEX IF NOT EXISTS `IDX_token_refresh_expires` ON `token` (`refreshExpiresAt`, `isRefreshTokenUsed`);

-- 사용자별 토큰 조회 최적화 - 분리된 인덱스로 구성하여 충돌 방지
CREATE INDEX IF NOT EXISTS `IDX_token_user_client_lookup` ON `token` (`userId`, `clientId`);
CREATE INDEX IF NOT EXISTS `IDX_token_status_expires` ON `token` (`isRevoked`, `expiresAt`);

-- Re-enable foreign key checks
SET FOREIGN_KEY_CHECKS = 1;

-- 5. 데이터 일관성 검증 쿼리들 (실행 후 확인용)

-- username 중복 확인
SELECT username, COUNT(*) as count 
FROM `user` 
GROUP BY username 
HAVING count > 1;

-- email 중복 확인
SELECT email, COUNT(*) as count 
FROM `user` 
GROUP BY email 
HAVING count > 1;

-- 토큰 패밀리 내 세대 중복 확인
SELECT tokenFamily, rotationGeneration, COUNT(*) as count 
FROM `token` 
WHERE tokenFamily IS NOT NULL
GROUP BY tokenFamily, rotationGeneration 
HAVING count > 1;

-- 만료된 토큰 정리 (필요한 경우)
UPDATE `token` 
SET isRevoked = 1, revokedReason = 'expired' 
WHERE expiresAt < NOW() AND isRevoked = 0;

-- Show final index structure
SELECT 'Final token table indexes:' as info;
SHOW INDEX FROM token;

-- Verify foreign key constraints are still intact
SELECT 'Foreign key constraints:' as info;
SELECT CONSTRAINT_NAME, TABLE_NAME, COLUMN_NAME, REFERENCED_TABLE_NAME, REFERENCED_COLUMN_NAME 
FROM INFORMATION_SCHEMA.KEY_COLUMN_USAGE 
WHERE TABLE_SCHEMA = 'flowauth' 
AND TABLE_NAME = 'token' 
AND REFERENCED_TABLE_NAME IS NOT NULL;

-- Commit the transaction
COMMIT;

SELECT 'Race condition prevention migration completed successfully!' as status;

-- 6. 트랜잭션 격리 수준 설정 (필요한 경우)
-- 애플리케이션 레벨에서도 설정하지만 DB 레벨에서도 보장
-- SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED;