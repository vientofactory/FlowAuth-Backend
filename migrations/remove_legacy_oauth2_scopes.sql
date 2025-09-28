-- Migration: Remove Legacy OAuth2 Scopes
-- Date: 2025-09-28
-- Description: Remove 'basic', 'read:user', 'read:profile' scopes from all OAuth2 related tables
-- This migration cleans up the database after simplifying the OAuth2 scope system to only use 'identify' and 'email' scopes

USE flowauth;

-- ===========================================
-- 1. CLIENT TABLE: Remove legacy scopes from client.scopes
-- ===========================================

-- First, let's see what scopes are currently stored in clients
SELECT
    id,
    clientId,
    name,
    scopes
FROM client
WHERE scopes IS NOT NULL
  AND (JSON_CONTAINS(scopes, JSON_QUOTE('basic'))
       OR JSON_CONTAINS(scopes, JSON_QUOTE('read:user'))
       OR JSON_CONTAINS(scopes, JSON_QUOTE('read:profile')));

-- Update client scopes to remove legacy scopes
UPDATE client
SET scopes = JSON_REMOVE(
    JSON_REMOVE(
        JSON_REMOVE(scopes, JSON_UNQUOTE(JSON_SEARCH(scopes, 'one', 'basic'))),
        JSON_UNQUOTE(JSON_SEARCH(scopes, 'one', 'read:user'))
    ),
    JSON_UNQUOTE(JSON_SEARCH(scopes, 'one', 'read:profile'))
)
WHERE scopes IS NOT NULL
  AND (JSON_CONTAINS(scopes, JSON_QUOTE('basic'))
       OR JSON_CONTAINS(scopes, JSON_QUOTE('read:user'))
       OR JSON_CONTAINS(scopes, JSON_QUOTE('read:profile')));

-- Verify client scopes cleanup
SELECT
    id,
    clientId,
    name,
    scopes
FROM client
WHERE scopes IS NOT NULL;

-- ===========================================
-- 2. TOKEN TABLE: Remove legacy scopes from token.scopes
-- ===========================================

-- First, let's see what scopes are currently stored in tokens
SELECT
    id,
    tokenType,
    scopes,
    isRevoked
FROM token
WHERE scopes IS NOT NULL
  AND (JSON_CONTAINS(scopes, JSON_QUOTE('basic'))
       OR JSON_CONTAINS(scopes, JSON_QUOTE('read:user'))
       OR JSON_CONTAINS(scopes, JSON_QUOTE('read:profile')));

-- Update token scopes to remove legacy scopes
UPDATE token
SET scopes = JSON_REMOVE(
    JSON_REMOVE(
        JSON_REMOVE(scopes, JSON_UNQUOTE(JSON_SEARCH(scopes, 'one', 'basic'))),
        JSON_UNQUOTE(JSON_SEARCH(scopes, 'one', 'read:user'))
    ),
    JSON_UNQUOTE(JSON_SEARCH(scopes, 'one', 'read:profile'))
)
WHERE scopes IS NOT NULL
  AND (JSON_CONTAINS(scopes, JSON_QUOTE('basic'))
       OR JSON_CONTAINS(scopes, JSON_QUOTE('read:user'))
       OR JSON_CONTAINS(scopes, JSON_QUOTE('read:profile')));

-- Verify token scopes cleanup
SELECT
    id,
    tokenType,
    scopes,
    isRevoked
FROM token
WHERE scopes IS NOT NULL;

-- ===========================================
-- 3. AUTHORIZATION_CODE TABLE: Remove legacy scopes from authorization_code.scopes
-- ===========================================

-- First, let's see what scopes are currently stored in authorization codes
SELECT
    id,
    code,
    scopes,
    isUsed
FROM authorization_code
WHERE scopes IS NOT NULL
  AND (JSON_CONTAINS(scopes, JSON_QUOTE('basic'))
       OR JSON_CONTAINS(scopes, JSON_QUOTE('read:user'))
       OR JSON_CONTAINS(scopes, JSON_QUOTE('read:profile')));

-- Update authorization code scopes to remove legacy scopes
UPDATE authorization_code
SET scopes = JSON_REMOVE(
    JSON_REMOVE(
        JSON_REMOVE(scopes, JSON_UNQUOTE(JSON_SEARCH(scopes, 'one', 'basic'))),
        JSON_UNQUOTE(JSON_SEARCH(scopes, 'one', 'read:user'))
    ),
    JSON_UNQUOTE(JSON_SEARCH(scopes, 'one', 'read:profile'))
)
WHERE scopes IS NOT NULL
  AND (JSON_CONTAINS(scopes, JSON_QUOTE('basic'))
       OR JSON_CONTAINS(scopes, JSON_QUOTE('read:user'))
       OR JSON_CONTAINS(scopes, JSON_QUOTE('read:profile')));

-- Verify authorization code scopes cleanup
SELECT
    id,
    code,
    scopes,
    isUsed
FROM authorization_code
WHERE scopes IS NOT NULL;

-- ===========================================
-- 4. CLEANUP: Remove empty scope arrays
-- ===========================================

-- Remove empty arrays from client scopes
UPDATE client
SET scopes = NULL
WHERE JSON_LENGTH(scopes) = 0;

-- Remove empty arrays from token scopes
UPDATE token
SET scopes = NULL
WHERE JSON_LENGTH(scopes) = 0;

-- Remove empty arrays from authorization_code scopes
UPDATE authorization_code
SET scopes = NULL
WHERE JSON_LENGTH(scopes) = 0;

-- ===========================================
-- 5. VERIFICATION QUERIES
-- ===========================================

-- Final verification: Check that no legacy scopes remain
SELECT 'CLIENTS WITH LEGACY SCOPES:' as check_type, COUNT(*) as count
FROM client
WHERE scopes IS NOT NULL
  AND (JSON_CONTAINS(scopes, JSON_QUOTE('basic'))
       OR JSON_CONTAINS(scopes, JSON_QUOTE('read:user'))
       OR JSON_CONTAINS(scopes, JSON_QUOTE('read:profile')))

UNION ALL

SELECT 'TOKENS WITH LEGACY SCOPES:' as check_type, COUNT(*) as count
FROM token
WHERE scopes IS NOT NULL
  AND (JSON_CONTAINS(scopes, JSON_QUOTE('basic'))
       OR JSON_CONTAINS(scopes, JSON_QUOTE('read:user'))
       OR JSON_CONTAINS(scopes, JSON_QUOTE('read:profile')))

UNION ALL

SELECT 'AUTH CODES WITH LEGACY SCOPES:' as check_type, COUNT(*) as count
FROM authorization_code
WHERE scopes IS NOT NULL
  AND (JSON_CONTAINS(scopes, JSON_QUOTE('basic'))
       OR JSON_CONTAINS(scopes, JSON_QUOTE('read:user'))
       OR JSON_CONTAINS(scopes, JSON_QUOTE('read:profile')));

-- Summary of remaining valid scopes
SELECT 'TOTAL CLIENTS:' as summary, COUNT(*) as count FROM client
UNION ALL
SELECT 'CLIENTS WITH SCOPES:', COUNT(*) FROM client WHERE scopes IS NOT NULL
UNION ALL
SELECT 'TOTAL TOKENS:', COUNT(*) FROM token
UNION ALL
SELECT 'TOKENS WITH SCOPES:', COUNT(*) FROM token WHERE scopes IS NOT NULL
UNION ALL
SELECT 'TOTAL AUTH CODES:', COUNT(*) FROM authorization_code
UNION ALL
SELECT 'AUTH CODES WITH SCOPES:', COUNT(*) FROM authorization_code WHERE scopes IS NOT NULL;