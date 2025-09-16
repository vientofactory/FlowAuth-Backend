-- 개발 환경 테스트용: ID 1번 계정에 최고 관리자 권한 부여
-- ROLES.ADMIN = 4095 (모든 권한의 OR 연산 결과)

UPDATE `user`
SET `permissions` = 4095
WHERE `id` = 1;

-- 권한 부여 확인
SELECT id, username, email, permissions
FROM `user`
WHERE `id` = 1;