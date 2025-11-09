-- Fix backupCodes column type from text to json
-- This SQL file manually applies only the backupCodes type fix from the migration

USE flowauth;

-- Start transaction
START TRANSACTION;

-- Drop and recreate the backupCodes column as JSON type
ALTER TABLE `user` DROP COLUMN `backupCodes`;
ALTER TABLE `user` ADD `backupCodes` json NULL;

-- Commit the changes
COMMIT;

-- Verify the change
SELECT 
    COLUMN_NAME, 
    DATA_TYPE, 
    IS_NULLABLE, 
    COLUMN_DEFAULT 
FROM 
    INFORMATION_SCHEMA.COLUMNS 
WHERE 
    TABLE_SCHEMA = 'flowauth' 
    AND TABLE_NAME = 'user' 
    AND COLUMN_NAME = 'backupCodes';