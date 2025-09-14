-- Migration: Update Token Columns to TEXT type
-- Date: 2025-09-15
-- Description: Increase column size for accessToken and refreshToken to accommodate JWT tokens

USE flowauth;

-- Check current table structure
SELECT COLUMN_NAME, DATA_TYPE, CHARACTER_MAXIMUM_LENGTH 
FROM INFORMATION_SCHEMA.COLUMNS 
WHERE TABLE_SCHEMA = 'flowauth' 
AND TABLE_NAME = 'token' 
AND COLUMN_NAME IN ('accessToken', 'refreshToken');

-- Update accessToken column to TEXT type
ALTER TABLE `token` MODIFY COLUMN `accessToken` TEXT NOT NULL;

-- Update refreshToken column to TEXT type  
ALTER TABLE `token` MODIFY COLUMN `refreshToken` TEXT NULL;

-- Verify the changes
SELECT COLUMN_NAME, DATA_TYPE, CHARACTER_MAXIMUM_LENGTH 
FROM INFORMATION_SCHEMA.COLUMNS 
WHERE TABLE_SCHEMA = 'flowauth' 
AND TABLE_NAME = 'token' 
AND COLUMN_NAME IN ('accessToken', 'refreshToken');

-- Show updated table structure
DESCRIBE `token`;