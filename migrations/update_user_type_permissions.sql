-- 사용자 권한 업데이트 마이그레이션
-- 실행일: 2025-10-27
-- 목적: regular와 developer 사용자 유형의 권한을 최신 권한 체계로 업데이트

-- 권한 상수 정의 (참고용)
-- READ_USER = 1 (1 << 0)
-- WRITE_USER = 2 (1 << 1)
-- DELETE_USER = 4 (1 << 2)
-- READ_CLIENT = 8 (1 << 3)
-- WRITE_CLIENT = 16 (1 << 4)
-- DELETE_CLIENT = 32 (1 << 5)
-- READ_TOKEN = 64 (1 << 6)
-- WRITE_TOKEN = 128 (1 << 7)
-- DELETE_TOKEN = 256 (1 << 8)
-- MANAGE_USERS = 512 (1 << 9)
-- MANAGE_SYSTEM = 1024 (1 << 10)
-- READ_DASHBOARD = 2048 (1 << 11)
-- WRITE_DASHBOARD = 4096 (1 << 12)
-- MANAGE_DASHBOARD = 8192 (1 << 13)
-- UPLOAD_FILE = 16384 (1 << 14)
-- ADMIN_ACCESS = 1073741824 (1 << 30)

-- 새로운 권한 계산:
-- REGULAR (USER 역할):
-- READ_CLIENT (8) + DELETE_CLIENT (32) + READ_TOKEN (64) + DELETE_TOKEN (256) + READ_DASHBOARD (2048) + UPLOAD_FILE (16384)
-- = 8 + 32 + 64 + 256 + 2048 + 16384 = 18792

-- DEVELOPER (CLIENT_MANAGER 역할):
-- READ_CLIENT (8) + WRITE_CLIENT (16) + DELETE_CLIENT (32) + READ_TOKEN (64) + WRITE_TOKEN (128) + DELETE_TOKEN (256)
-- + READ_DASHBOARD (2048) + WRITE_DASHBOARD (4096) + UPLOAD_FILE (16384)
-- = 8 + 16 + 32 + 64 + 128 + 256 + 2048 + 4096 + 16384 = 23032

-- 데이터베이스 선택
USE flowauth;

-- 백업 테이블 생성 (롤백을 위해)
CREATE TABLE user_permissions_backup_20251027 AS
SELECT id, userType, permissions, updatedAt
FROM user;

-- 현재 권한 상태 확인 (업데이트 전)
SELECT
    userType,
    COUNT(*) as user_count,
    permissions,
    CASE
        WHEN permissions = 18792 THEN 'Regular User (Current)'
        WHEN permissions = 23032 THEN 'Developer User (Current)'
        WHEN permissions = 1073741824 THEN 'Admin User'
        ELSE CONCAT('Other/Legacy: ', permissions)
    END as permission_status
FROM user
GROUP BY userType, permissions
ORDER BY userType, permissions;

-- regular 사용자 권한 업데이트
UPDATE user
SET permissions = 18792,
    updatedAt = NOW()
WHERE userType = 'regular'
  AND permissions != 1073741824; -- ADMIN 사용자는 제외

-- developer 사용자 권한 업데이트
UPDATE user
SET permissions = 23032,
    updatedAt = NOW()
WHERE userType = 'developer'
  AND permissions != 1073741824; -- ADMIN 사용자는 제외

-- 업데이트 결과 확인 (업데이트 후)
SELECT
    userType,
    COUNT(*) as user_count,
    permissions,
    CASE
        WHEN permissions = 18792 THEN 'Regular User (Updated)'
        WHEN permissions = 23032 THEN 'Developer User (Updated)'
        WHEN permissions = 1073741824 THEN 'Admin User (Unchanged)'
        ELSE CONCAT('Other: ', permissions)
    END as permission_status
FROM user
GROUP BY userType, permissions
ORDER BY userType, permissions;

-- 업데이트된 사용자 수 확인
SELECT
    'Regular users updated' as operation,
    COUNT(*) as count
FROM user
WHERE userType = 'regular' AND permissions = 18792

UNION ALL

SELECT
    'Developer users updated' as operation,
    COUNT(*) as count
FROM user
WHERE userType = 'developer' AND permissions = 23032

UNION ALL

SELECT
    'Admin users unchanged' as operation,
    COUNT(*) as count
FROM user
WHERE permissions = 1073741824;

-- 롤백용 SQL (문제가 있을 경우 실행)
/*
-- 백업에서 복원
UPDATE user u
JOIN user_permissions_backup_20251027 b ON u.id = b.id
SET u.permissions = b.permissions,
    u.updatedAt = b.updatedAt
WHERE u.permissions != 1073741824; -- 관리자는 변경하지 않음

-- 백업 테이블 삭제 (롤백 완료 후)
-- DROP TABLE user_permissions_backup_20251027;
*/