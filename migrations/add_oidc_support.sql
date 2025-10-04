-- Migration: Add OIDC Support to AuthorizationCode Table
-- Date: 2025-10-03
-- Description: Add nonce and authTime columns to authorization_code table for OIDC support

USE flowauth;

-- ===========================================
-- 1. ADD OIDC COLUMNS TO AUTHORIZATION_CODE TABLE
-- ===========================================

-- Check current table structure
SELECT 'CURRENT AUTHORIZATION_CODE TABLE STRUCTURE:' as info;
DESCRIBE authorization_code;

-- Add nonce column for OIDC (replay attack prevention)
ALTER TABLE authorization_code
ADD COLUMN nonce VARCHAR(128) NULL COMMENT 'OIDC nonce parameter for replay attack prevention';

-- Add authTime column for OIDC (authentication time)
ALTER TABLE authorization_code
ADD COLUMN authTime BIGINT NULL COMMENT 'OIDC authentication time (Unix timestamp)';

-- Add index on nonce for performance
CREATE INDEX idx_authorization_code_nonce ON authorization_code(nonce);

-- Verify the changes
SELECT 'UPDATED AUTHORIZATION_CODE TABLE STRUCTURE:' as info;
DESCRIBE authorization_code;

-- ===========================================
-- 2. ADD OIDC SCOPES TO SCOPE TABLE (IF NOT EXISTS)
-- ===========================================

-- Check current scopes
SELECT 'CURRENT SCOPES IN DATABASE:' as info;
SELECT id, name, description, isDefault, isActive FROM scope ORDER BY name;

-- Insert OIDC scopes if they don't exist
INSERT IGNORE INTO scope (name, description, isDefault, isActive, createdAt, updatedAt)
VALUES
  ('openid', 'OpenID Connect 인증을 위한 기본 스코프', 1, 1, NOW(), NOW()),
  ('identify', '사용자 기본 정보 (ID, 이름 등) 접근', 1, 1, NOW(), NOW()),
  ('email', '사용자 이메일 주소 접근', 1, 1, NOW(), NOW());

-- Verify scopes were added
SELECT 'SCOPES AFTER OIDC ADDITION:' as info;
SELECT id, name, description, isDefault, isActive FROM scope ORDER BY name;

-- ===========================================
-- 3. MIGRATION VERIFICATION
-- ===========================================

-- Show final table structures
SELECT 'FINAL AUTHORIZATION_CODE TABLE:' as info;
DESCRIBE authorization_code;

SELECT 'FINAL SCOPE TABLE:' as info;
DESCRIBE scope;

-- Show migration summary
SELECT
  'OIDC MIGRATION COMPLETED SUCCESSFULLY' as status,
  COUNT(*) as total_scopes
FROM scope
WHERE name IN ('openid', 'identify', 'email');