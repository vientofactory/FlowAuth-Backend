-- Migration: Add OIDC Support (DRY RUN)
-- Date: 2025-01-15
-- Description: Preview current database state before OIDC support migration
-- This is a read-only version that shows what the database looks like currently

USE flowauth;

-- ===========================================
-- DRY RUN: OIDC SUPPORT MIGRATION PREVIEW
-- ===========================================

SELECT '=== DRY RUN: OIDC SUPPORT MIGRATION PREVIEW ===' as preview_title;

-- Current authorization_code table structure
SELECT 'CURRENT AUTHORIZATION_CODE TABLE STRUCTURE:' as section;
DESCRIBE authorization_code;

-- Check if OIDC columns already exist
SELECT 'OIDC COLUMNS EXISTENCE CHECK:' as section;
SELECT
    'nonce column exists' as check_type,
    COUNT(*) > 0 as exists_flag
FROM information_schema.COLUMNS
WHERE TABLE_SCHEMA = DATABASE()
  AND TABLE_NAME = 'authorization_code'
  AND COLUMN_NAME = 'nonce'

UNION ALL

SELECT
    'authTime column exists' as check_type,
    COUNT(*) > 0 as exists_flag
FROM information_schema.COLUMNS
WHERE TABLE_SCHEMA = DATABASE()
  AND TABLE_NAME = 'authorization_code'
  AND COLUMN_NAME = 'authTime'

UNION ALL

SELECT
    'nonce index exists' as check_type,
    COUNT(*) > 0 as exists_flag
FROM information_schema.STATISTICS
WHERE TABLE_SCHEMA = DATABASE()
  AND TABLE_NAME = 'authorization_code'
  AND INDEX_NAME = 'idx_authorization_code_nonce';

-- Current scope table state
SELECT 'CURRENT SCOPE TABLE STATE:' as section;
SELECT id, name, description, isActive, createdAt
FROM scope
ORDER BY name;

-- Check existing OIDC scopes
SELECT 'EXISTING OIDC SCOPES CHECK:' as section;
SELECT
    'openid scope exists' as check_type,
    COUNT(*) > 0 as exists_flag
FROM scope
WHERE name = 'openid'

UNION ALL

SELECT
    'identify scope exists' as check_type,
    COUNT(*) > 0 as exists_flag
FROM scope
WHERE name = 'identify'

UNION ALL

SELECT
    'email scope exists' as check_type,
    COUNT(*) > 0 as exists_flag
FROM scope
WHERE name = 'email';

-- Sample authorization codes to show current data
SELECT 'SAMPLE AUTHORIZATION CODES (CURRENT STATE):' as section;
SELECT
    id,
    LEFT(code, 12) as code_prefix,
    scopes,
    expiresAt,
    isUsed,
    createdAt
FROM authorization_code
ORDER BY createdAt DESC
LIMIT 5;

-- Show what the authorization_code table will look like after migration
SELECT 'AFTER MIGRATION PREVIEW - TABLE STRUCTURE:' as section;
SELECT
    'Column additions preview:' as preview,
    'nonce VARCHAR(128) NULL - For CSRF protection' as nonce_column,
    'authTime BIGINT NULL - Authentication timestamp' as authTime_column,
    'idx_authorization_code_nonce INDEX - Performance optimization' as nonce_index;

-- Show what OIDC scopes will be added
SELECT 'OIDC SCOPES TO BE ADDED:' as section;
SELECT
    'openid' as scope_name,
    'Required for OIDC compliance' as description,
    TRUE as isActive
UNION ALL
SELECT
    'identify' as scope_name,
    'User identity information access' as description,
    TRUE as isActive
UNION ALL
SELECT
    'email' as scope_name,
    'User email address access' as description,
    TRUE as isActive;

-- Summary statistics
SELECT '=== SUMMARY STATISTICS ===' as summary_title;

SELECT 'TOTAL AUTHORIZATION CODES:' as metric, COUNT(*) as count FROM authorization_code
UNION ALL
SELECT 'TOTAL SCOPES:' as metric, COUNT(*) as count FROM scope
UNION ALL
SELECT 'OIDC SCOPES ALREADY EXIST:' as metric,
       COUNT(*) as count
FROM scope
WHERE name IN ('openid', 'identify', 'email')
UNION ALL
SELECT 'NON-OIDC SCOPES:' as metric,
       COUNT(*) as count
FROM scope
WHERE name NOT IN ('openid', 'identify', 'email');

-- Migration impact assessment
SELECT '=== MIGRATION IMPACT ASSESSMENT ===' as impact_title;

SELECT
    'Database changes required:' as assessment,
    CASE
        WHEN (
            SELECT COUNT(*) FROM information_schema.COLUMNS
            WHERE TABLE_SCHEMA = DATABASE()
              AND TABLE_NAME = 'authorization_code'
              AND COLUMN_NAME IN ('nonce', 'authTime')
        ) = 2 THEN 'NONE - OIDC columns already exist'
        ELSE 'ADD COLUMNS - nonce and authTime to authorization_code table'
    END as table_changes,

    CASE
        WHEN (
            SELECT COUNT(*) FROM information_schema.STATISTICS
            WHERE TABLE_SCHEMA = DATABASE()
              AND TABLE_NAME = 'authorization_code'
              AND INDEX_NAME = 'idx_authorization_code_nonce'
        ) > 0 THEN 'NONE - Index already exists'
        ELSE 'ADD INDEX - idx_authorization_code_nonce'
    END as index_changes,

    CASE
        WHEN (
            SELECT COUNT(*) FROM scope
            WHERE name IN ('openid', 'identify', 'email')
        ) = 3 THEN 'NONE - All OIDC scopes already exist'
        ELSE 'ADD SCOPES - Missing OIDC scopes will be inserted'
    END as scope_changes;

-- Compatibility check
SELECT '=== BACKWARD COMPATIBILITY CHECK ===' as compatibility_title;

SELECT
    'Existing OAuth2 flows:' as check_type,
    'COMPATIBLE - OIDC changes are additive only' as status
UNION ALL
SELECT
    'Existing authorization codes:' as check_type,
    'COMPATIBLE - New columns are nullable' as status
UNION ALL
SELECT
    'Existing scopes:' as check_type,
    'COMPATIBLE - OIDC scopes added alongside existing ones' as status
UNION ALL
SELECT
    'Database performance:' as check_type,
    'IMPACT - New index may improve query performance' as status;