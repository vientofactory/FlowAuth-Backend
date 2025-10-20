-- Migration: Remove 'identify' legacy scope
-- This migration removes the legacy 'identify' scope from the database
-- and migrates any existing client scopes to use 'profile' instead

-- Start transaction
START TRANSACTION;

-- 1. Update clients that use 'identify' scope to use 'profile' instead
UPDATE client SET 
    scopes = REPLACE(scopes, 'identify', 'profile')
WHERE 
    FIND_IN_SET('identify', scopes) > 0 
    AND FIND_IN_SET('profile', scopes) = 0;

-- 2. For clients that already have 'profile' scope, remove 'identify'
UPDATE client SET 
    scopes = TRIM(BOTH ',' FROM REPLACE(CONCAT(',', scopes, ','), ',identify,', ','))
WHERE 
    FIND_IN_SET('identify', scopes) > 0 
    AND FIND_IN_SET('profile', scopes) > 0;

-- 3. Remove the 'identify' scope from the scope table
DELETE FROM scope WHERE name = 'identify';

-- Commit transaction
COMMIT;

-- Verify the migration
SELECT 
    'Migration completed' as status,
    (SELECT COUNT(*) FROM scope WHERE name = 'identify') as identify_scopes_remaining,
    (SELECT COUNT(*) FROM client WHERE FIND_IN_SET('identify', scopes) > 0) as clients_with_identify_scope;