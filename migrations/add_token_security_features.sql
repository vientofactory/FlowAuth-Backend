-- Enhanced Token Family and Rotation Security Migration
-- Adds token family tracking and rotation generation fields for enhanced refresh token security

USE flowauth;

-- Create a temporary procedure to handle conditional column additions
DELIMITER //
CREATE PROCEDURE AddTokenSecurityColumns()
BEGIN
    DECLARE col_exists INT DEFAULT 0;
    
    -- Add revokedReason column if it doesn't exist
    SELECT COUNT(*) INTO col_exists 
    FROM information_schema.columns 
    WHERE table_schema = 'flowauth' 
    AND table_name = 'token' 
    AND column_name = 'revokedReason';
    
    IF col_exists = 0 THEN
        ALTER TABLE `token` ADD COLUMN `revokedReason` varchar(255) NULL AFTER `isRefreshTokenUsed`;
    END IF;
    
    -- Add tokenFamily column if it doesn't exist
    SELECT COUNT(*) INTO col_exists 
    FROM information_schema.columns 
    WHERE table_schema = 'flowauth' 
    AND table_name = 'token' 
    AND column_name = 'tokenFamily';
    
    IF col_exists = 0 THEN
        ALTER TABLE `token` ADD COLUMN `tokenFamily` varchar(255) NULL;
    END IF;
    
    -- Add rotationGeneration column if it doesn't exist
    SELECT COUNT(*) INTO col_exists 
    FROM information_schema.columns 
    WHERE table_schema = 'flowauth' 
    AND table_name = 'token' 
    AND column_name = 'rotationGeneration';
    
    IF col_exists = 0 THEN
        ALTER TABLE `token` ADD COLUMN `rotationGeneration` int NOT NULL DEFAULT 1;
    END IF;
END //
DELIMITER ;

-- Execute the procedure and then drop it
CALL AddTokenSecurityColumns();
DROP PROCEDURE AddTokenSecurityColumns;

-- Create indexes using a temporary procedure
DELIMITER //
CREATE PROCEDURE AddTokenSecurityIndexes()
BEGIN
    DECLARE index_exists INT DEFAULT 0;
    
    -- Check and create index for token family queries
    SELECT COUNT(*) INTO index_exists 
    FROM information_schema.statistics 
    WHERE table_schema = 'flowauth' 
    AND table_name = 'token' 
    AND index_name = 'IDX_token_family';
    
    IF index_exists = 0 THEN
        CREATE INDEX `IDX_token_family` ON `token` (`tokenFamily`);
    END IF;
    
    -- Check and create index for revoked tokens cleanup
    SELECT COUNT(*) INTO index_exists 
    FROM information_schema.statistics 
    WHERE table_schema = 'flowauth' 
    AND table_name = 'token' 
    AND index_name = 'IDX_token_revoked';
    
    IF index_exists = 0 THEN
        CREATE INDEX `IDX_token_revoked` ON `token` (`isRevoked`, `revokedAt`);
    END IF;
    
    -- Check and create index for token rotation generation
    SELECT COUNT(*) INTO index_exists 
    FROM information_schema.statistics 
    WHERE table_schema = 'flowauth' 
    AND table_name = 'token' 
    AND index_name = 'IDX_token_rotation';
    
    IF index_exists = 0 THEN
        CREATE INDEX `IDX_token_rotation` ON `token` (`tokenFamily`, `rotationGeneration`);
    END IF;
END //
DELIMITER ;

-- Execute the procedure and then drop it
CALL AddTokenSecurityIndexes();
DROP PROCEDURE AddTokenSecurityIndexes;

-- Update existing tokens to have default values
UPDATE `token` 
SET `rotationGeneration` = 1 
WHERE `rotationGeneration` IS NULL;

-- Create a stored procedure for token family cleanup (optional optimization)
-- Drop procedure if it exists first, then create it
DROP PROCEDURE IF EXISTS CleanupRevokedTokens;

DELIMITER //
CREATE PROCEDURE CleanupRevokedTokens()
BEGIN
    -- Remove revoked tokens older than 30 days
    DELETE FROM `token` 
    WHERE `isRevoked` = 1 
    AND `revokedAt` < DATE_SUB(NOW(), INTERVAL 30 DAY);
    
    -- Remove expired refresh tokens older than 7 days
    DELETE FROM `token` 
    WHERE `refreshExpiresAt` < DATE_SUB(NOW(), INTERVAL 7 DAY);
END //
DELIMITER ;

-- Add comments for new columns
ALTER TABLE `token` 
MODIFY COLUMN `revokedReason` varchar(255) NULL COMMENT 'Reason why token was revoked (security, user_action, etc.)',
MODIFY COLUMN `tokenFamily` varchar(255) NULL COMMENT 'UUID identifying token family for rotation tracking',
MODIFY COLUMN `rotationGeneration` int NOT NULL DEFAULT 1 COMMENT 'Generation number for token rotation security';