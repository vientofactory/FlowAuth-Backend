-- Migration: AddResponseTypeToAuthorizationCode
-- Created: 2025-10-25
-- Description: Add responseType column to authorization_code table for Hybrid Flow support

USE flowauth;

-- Up migration: Add responseType column
ALTER TABLE authorization_code ADD COLUMN responseType varchar(50) NULL;

-- Down migration: Remove responseType column
-- ALTER TABLE authorization_code DROP COLUMN responseType;