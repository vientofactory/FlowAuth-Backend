-- Migration: Remove Legacy OAuth2 Scopes (DRY RUN)
-- Date: 2025-09-28
-- Description: Preview what would be changed by the legacy scopes removal migration
-- This is a read-only version that shows what data would be affected

USE flowauth;

-- ===========================================
-- DRY RUN: Preview what will be changed
-- ===========================================

SELECT '=== DRY RUN: LEGACY SCOPES REMOVAL PREVIEW ===' as preview_title;

-- Show clients that would be affected
SELECT 'CLIENTS THAT WOULD BE AFFECTED:' as section;
SELECT
    id,
    clientId,
    name,
    scopes as current_scopes,
    CASE
        WHEN JSON_CONTAINS(scopes, JSON_QUOTE('basic')) THEN 'CONTAINS BASIC'
        WHEN JSON_CONTAINS(scopes, JSON_QUOTE('read:user')) THEN 'CONTAINS READ:USER'
        WHEN JSON_CONTAINS(scopes, JSON_QUOTE('read:profile')) THEN 'CONTAINS READ:PROFILE'
        ELSE 'MULTIPLE LEGACY SCOPES'
    END as issue_type
FROM client
WHERE scopes IS NOT NULL
  AND (JSON_CONTAINS(scopes, JSON_QUOTE('basic'))
       OR JSON_CONTAINS(scopes, JSON_QUOTE('read:user'))
       OR JSON_CONTAINS(scopes, JSON_QUOTE('read:profile')));

-- Show what client scopes would become after removal
SELECT 'CLIENT SCOPES AFTER REMOVAL PREVIEW:' as section;
SELECT
    id,
    clientId,
    name,
    scopes as current_scopes,
    JSON_REMOVE(
        JSON_REMOVE(
            JSON_REMOVE(scopes, JSON_UNQUOTE(JSON_SEARCH(scopes, 'one', 'basic'))),
            JSON_UNQUOTE(JSON_SEARCH(scopes, 'one', 'read:user'))
        ),
        JSON_UNQUOTE(JSON_SEARCH(scopes, 'one', 'read:profile'))
    ) as scopes_after_removal
FROM client
WHERE scopes IS NOT NULL
  AND (JSON_CONTAINS(scopes, JSON_QUOTE('basic'))
       OR JSON_CONTAINS(scopes, JSON_QUOTE('read:user'))
       OR JSON_CONTAINS(scopes, JSON_QUOTE('read:profile')));

-- Show tokens that would be affected
SELECT 'TOKENS THAT WOULD BE AFFECTED:' as section;
SELECT
    id,
    tokenType,
    scopes as current_scopes,
    isRevoked,
    CASE
        WHEN JSON_CONTAINS(scopes, JSON_QUOTE('basic')) THEN 'CONTAINS BASIC'
        WHEN JSON_CONTAINS(scopes, JSON_QUOTE('read:user')) THEN 'CONTAINS READ:USER'
        WHEN JSON_CONTAINS(scopes, JSON_QUOTE('read:profile')) THEN 'CONTAINS READ:PROFILE'
        ELSE 'MULTIPLE LEGACY SCOPES'
    END as issue_type
FROM token
WHERE scopes IS NOT NULL
  AND (JSON_CONTAINS(scopes, JSON_QUOTE('basic'))
       OR JSON_CONTAINS(scopes, JSON_QUOTE('read:user'))
       OR JSON_CONTAINS(scopes, JSON_QUOTE('read:profile')));

-- Show authorization codes that would be affected
SELECT 'AUTHORIZATION CODES THAT WOULD BE AFFECTED:' as section;
SELECT
    id,
    LEFT(code, 10) as code_prefix,
    scopes as current_scopes,
    isUsed,
    CASE
        WHEN JSON_CONTAINS(scopes, JSON_QUOTE('basic')) THEN 'CONTAINS BASIC'
        WHEN JSON_CONTAINS(scopes, JSON_QUOTE('read:user')) THEN 'CONTAINS READ:USER'
        WHEN JSON_CONTAINS(scopes, JSON_QUOTE('read:profile')) THEN 'CONTAINS READ:PROFILE'
        ELSE 'MULTIPLE LEGACY SCOPES'
    END as issue_type
FROM authorization_code
WHERE scopes IS NOT NULL
  AND (JSON_CONTAINS(scopes, JSON_QUOTE('basic'))
       OR JSON_CONTAINS(scopes, JSON_QUOTE('read:user'))
       OR JSON_CONTAINS(scopes, JSON_QUOTE('read:profile')));

-- Summary statistics
SELECT '=== SUMMARY STATISTICS ===' as summary_title;

SELECT 'TOTAL CLIENTS:' as metric, COUNT(*) as count FROM client
UNION ALL
SELECT 'CLIENTS WITH LEGACY SCOPES:', COUNT(*) FROM client
WHERE scopes IS NOT NULL
  AND (JSON_CONTAINS(scopes, JSON_QUOTE('basic'))
       OR JSON_CONTAINS(scopes, JSON_QUOTE('read:user'))
       OR JSON_CONTAINS(scopes, JSON_QUOTE('read:profile')))

UNION ALL
SELECT 'TOTAL TOKENS:', COUNT(*) FROM token
UNION ALL
SELECT 'TOKENS WITH LEGACY SCOPES:', COUNT(*) FROM token
WHERE scopes IS NOT NULL
  AND (JSON_CONTAINS(scopes, JSON_QUOTE('basic'))
       OR JSON_CONTAINS(scopes, JSON_QUOTE('read:user'))
       OR JSON_CONTAINS(scopes, JSON_QUOTE('read:profile')))

UNION ALL
SELECT 'TOTAL AUTH CODES:', COUNT(*) FROM authorization_code
UNION ALL
SELECT 'AUTH CODES WITH LEGACY SCOPES:', COUNT(*) FROM authorization_code
WHERE scopes IS NOT NULL
  AND (JSON_CONTAINS(scopes, JSON_QUOTE('basic'))
       OR JSON_CONTAINS(scopes, JSON_QUOTE('read:user'))
       OR JSON_CONTAINS(scopes, JSON_QUOTE('read:profile')));

-- Show what valid scopes remain after cleanup
SELECT '=== REMAINING VALID SCOPES PREVIEW ===' as remaining_title;

SELECT 'CLIENTS WITH VALID SCOPES ONLY:' as section;
SELECT id, clientId, name, scopes
FROM client
WHERE scopes IS NOT NULL
  AND NOT (JSON_CONTAINS(scopes, JSON_QUOTE('basic'))
           OR JSON_CONTAINS(scopes, JSON_QUOTE('read:user'))
           OR JSON_CONTAINS(scopes, JSON_QUOTE('read:profile')));

SELECT 'TOKENS WITH VALID SCOPES ONLY:' as section;
SELECT id, tokenType, scopes, isRevoked
FROM token
WHERE scopes IS NOT NULL
  AND NOT (JSON_CONTAINS(scopes, JSON_QUOTE('basic'))
           OR JSON_CONTAINS(scopes, JSON_QUOTE('read:user'))
           OR JSON_CONTAINS(scopes, JSON_QUOTE('read:profile')));

SELECT 'AUTH CODES WITH VALID SCOPES ONLY:' as section;
SELECT id, LEFT(code, 10) as code_prefix, scopes, isUsed
FROM authorization_code
WHERE scopes IS NOT NULL
  AND NOT (JSON_CONTAINS(scopes, JSON_QUOTE('basic'))
           OR JSON_CONTAINS(scopes, JSON_QUOTE('read:user'))
           OR JSON_CONTAINS(scopes, JSON_QUOTE('read:profile')));