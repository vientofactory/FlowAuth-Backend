-- Migration: UpdateClientForeignKeys1760000000001
-- Description: Updates foreign key constraints for token and authorization_code tables to use CASCADE DELETE
-- Date: 2025-10-25

-- Update token table foreign key to CASCADE DELETE
-- Step 1: Drop existing foreign key
ALTER TABLE token DROP FOREIGN KEY `FK_8139f8b076cfd8723e992c9d9ff`;

-- Step 2: Add new foreign key with CASCADE DELETE
ALTER TABLE token
ADD CONSTRAINT FK_token_client
FOREIGN KEY (clientId) REFERENCES client(id) ON DELETE CASCADE;

-- Update authorization_code table foreign key to CASCADE DELETE
-- Step 1: Drop existing foreign key
ALTER TABLE authorization_code DROP FOREIGN KEY `FK_ffbeadc85eea5dabbbcaf4f6b0e992c9d9ff`;

-- Step 2: Add new foreign key with CASCADE DELETE
ALTER TABLE authorization_code
ADD CONSTRAINT FK_authorization_code_client
FOREIGN KEY (clientId) REFERENCES client(id) ON DELETE CASCADE;

-- Record the migration as executed (if using manual migration tracking)
-- INSERT INTO `migrations` (`timestamp`, `name`) VALUES (1760000000001, 'UpdateClientForeignKeys1760000000001');