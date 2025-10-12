-- 권한 시스템 마이그레이션: ADMIN_ACCESS 비트 31 → 30 변경
-- 실행 전 주의사항:
-- 1. 데이터베이스 백업 수행
-- 2. 애플리케이션 다운타임 계획
-- 3. 롤백 계획 준비

-- Migration: ADMIN_ACCESS 비트 위치 변경 (31 → 30)
-- Date: 2024-10-12
-- Breaking Change: Yes
-- Reason: JavaScript 32-bit integer compatibility

BEGIN;

-- 1. 현재 ADMIN 사용자 확인 (마이그레이션 전)
SELECT 
    id,
    username,
    email,
    permissions,
    (permissions & (1 << 31)) > 0 as has_old_admin_access,
    (permissions & (1 << 30)) > 0 as has_new_admin_access
FROM users 
WHERE (permissions & (1 << 31)) > 0;

-- 2. ADMIN_ACCESS 비트 위치 변경 (31번째 비트 → 30번째 비트)
UPDATE users 
SET 
    permissions = (permissions & ~(1 << 31)) | (1 << 30),
    updated_at = NOW()
WHERE (permissions & (1 << 31)) > 0;

-- 3. 변경 결과 확인
SELECT 
    id,
    username,
    email,
    permissions,
    (permissions & (1 << 31)) > 0 as has_old_admin_access,
    (permissions & (1 << 30)) > 0 as has_new_admin_access
FROM users 
WHERE (permissions & (1 << 30)) > 0;

-- 4. 변경된 사용자 수 확인
SELECT COUNT(*) as migrated_admin_users
FROM users 
WHERE (permissions & (1 << 30)) > 0;

-- 5. 데이터 무결성 검증
-- 31번째 비트를 사용하는 사용자가 더 이상 없는지 확인
SELECT COUNT(*) as remaining_old_admin_users
FROM users 
WHERE (permissions & (1 << 31)) > 0;

-- 6. 마이그레이션 로그 기록 (로그 테이블이 있는 경우)
INSERT INTO migration_logs (
    migration_name,
    description,
    executed_at,
    affected_rows
) 
SELECT 
    'admin_access_bit_migration_31_to_30',
    'Changed ADMIN_ACCESS from bit 31 to bit 30 for JavaScript compatibility',
    NOW(),
    COUNT(*)
FROM users 
WHERE (permissions & (1 << 30)) > 0;

COMMIT;

-- 롤백 스크립트 (긴급 시 사용)
/*
BEGIN;

-- ADMIN_ACCESS 비트 위치 되돌리기 (30번째 비트 → 31번째 비트)
UPDATE users 
SET 
    permissions = (permissions & ~(1 << 30)) | (1 << 31),
    updated_at = NOW()
WHERE (permissions & (1 << 30)) > 0;

-- 롤백 확인
SELECT 
    id,
    username,
    email,
    permissions,
    (permissions & (1 << 31)) > 0 as has_old_admin_access,
    (permissions & (1 << 30)) > 0 as has_new_admin_access
FROM users 
WHERE (permissions & (1 << 31)) > 0;

COMMIT;
*/

-- 마이그레이션 후 테스트 쿼리들
-- 1. ADMIN 권한 사용자 조회
-- SELECT * FROM users WHERE permissions & (1 << 30) > 0;

-- 2. 특정 사용자의 권한 확인
-- SELECT 
--     username,
--     permissions,
--     (permissions & (1 << 30)) > 0 as is_admin
-- FROM users 
-- WHERE username = 'admin_username';

-- 3. 권한별 사용자 수 통계
-- SELECT 
--     'ADMIN_ACCESS' as permission_name,
--     COUNT(*) as user_count
-- FROM users 
-- WHERE permissions & (1 << 30) > 0;