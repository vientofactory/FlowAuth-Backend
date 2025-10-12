-- 사용자 권한 업데이트 마이그레이션
-- 실행일: 2025-10-12
-- 목적: 기존 사용자들의 권한을 새로운 권한 체계로 업데이트

-- 권한 상수 정의 (참고용)
-- READ_USER = 1
-- WRITE_USER = 2  
-- DELETE_USER = 4
-- READ_CLIENT = 8
-- WRITE_CLIENT = 16
-- DELETE_CLIENT = 32
-- READ_TOKEN = 64
-- WRITE_TOKEN = 128
-- DELETE_TOKEN = 256
-- MANAGE_USERS = 512
-- MANAGE_SYSTEM = 1024
-- READ_DASHBOARD = 2048
-- WRITE_DASHBOARD = 4096
-- MANAGE_DASHBOARD = 8192
-- UPLOAD_FILE = 16384
-- ADMIN_ACCESS = 1073741824 (1 << 30, JavaScript 비트 연산 호환성을 위해 변경)

-- 새로운 일반 사용자 권한 계산:
-- READ_USER (1) + READ_DASHBOARD (2048) + READ_CLIENT (8) + WRITE_CLIENT (16) + READ_TOKEN (64) + DELETE_TOKEN (256)
-- = 1 + 2048 + 8 + 16 + 64 + 256 = 2393

-- 새로운 개발자 사용자 권한 계산:
-- READ_CLIENT (8) + WRITE_CLIENT (16) + DELETE_CLIENT (32) + READ_TOKEN (64) + WRITE_TOKEN (128) + DELETE_TOKEN (256) + READ_DASHBOARD (2048) + WRITE_DASHBOARD (4096) + UPLOAD_FILE (16384)
-- = 8 + 16 + 32 + 64 + 128 + 256 + 2048 + 4096 + 16384 = 23032

-- 데이터베이스 선택
USE flowauth;

-- 백업 테이블 생성 (롤백을 위해)
CREATE TABLE user_permissions_backup_20251012 AS 
SELECT id, userType, permissions, updatedAt 
FROM user;

-- 기존 잘못된 ADMIN_ACCESS 값 (2147483648) 수정
-- JavaScript 비트 연산 문제로 인해 새로운 값 (1073741824)로 변경
UPDATE user 
SET permissions = 1073741824,
    updatedAt = NOW()
WHERE permissions = 2147483648;

-- 일반 사용자(regular) 권한 업데이트
UPDATE user 
SET permissions = 2393, 
    updatedAt = NOW()
WHERE userType = 'regular' 
  AND permissions != 1073741824; -- ADMIN_ACCESS가 아닌 경우만

-- 개발자 사용자(developer) 권한 업데이트  
UPDATE user 
SET permissions = 23032,
    updatedAt = NOW()
WHERE userType = 'developer' 
  AND permissions != 1073741824; -- ADMIN_ACCESS가 아닌 경우만

-- 업데이트 결과 확인
SELECT 
    userType,
    COUNT(*) as user_count,
    permissions,
    CASE 
        WHEN permissions = 2393 THEN 'Regular User (Updated)'
        WHEN permissions = 23032 THEN 'Developer User (Updated)'
        WHEN permissions = 1073741824 THEN 'Admin User (Fixed)'
        WHEN permissions = 2147483648 THEN 'Admin User (Old - Should be fixed)'
        ELSE CONCAT('Other: ', permissions)
    END as permission_type
FROM user 
GROUP BY userType, permissions
ORDER BY userType, permissions;

-- 롤백용 SQL (문제가 있을 경우 실행)
/*
UPDATE user u
JOIN user_permissions_backup_20251012 b ON u.id = b.id
SET u.permissions = b.permissions,
    u.updatedAt = b.updatedAt
WHERE u.permissions != 1073741824; -- 관리자는 변경하지 않음

-- 백업 테이블 삭제 (롤백 완료 후)
-- DROP TABLE user_permissions_backup_20251012;
*/