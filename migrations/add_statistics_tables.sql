-- Migration: Add Statistics Tables
-- Description: Create tables for storing historical token, scope, and client statistics
-- Date: 2025-01-28
-- Purpose: Enable persistent statistics that survive token deletion/expiration

USE flowauth;

-- Create token_statistics table
CREATE TABLE `token_statistics` (
    `id` int NOT NULL AUTO_INCREMENT,
    `userId` int NOT NULL,
    `clientId` int NULL,
    `eventType` enum('issued','revoked','expired') NOT NULL,
    `eventDate` date NOT NULL,
    `count` int NOT NULL DEFAULT 1,
    `revokedReason` varchar(500) NULL,
    `createdAt` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (`id`)
) ENGINE=InnoDB;

-- Create indexes for token_statistics
CREATE INDEX `IDX_token_statistics_user_client_event_date` ON `token_statistics` (`userId`, `clientId`, `eventType`, `eventDate`);
CREATE INDEX `IDX_token_statistics_event_date` ON `token_statistics` (`eventDate`);
CREATE INDEX `IDX_token_statistics_user_id` ON `token_statistics` (`userId`);
CREATE INDEX `IDX_token_statistics_client_id` ON `token_statistics` (`clientId`);

-- Create scope_statistics table
CREATE TABLE `scope_statistics` (
    `id` int NOT NULL AUTO_INCREMENT,
    `userId` int NOT NULL,
    `scope` varchar(100) NOT NULL,
    `eventType` enum('granted','revoked') NOT NULL,
    `eventDate` date NOT NULL,
    `count` int NOT NULL DEFAULT 1,
    `createdAt` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (`id`)
) ENGINE=InnoDB;

-- Create indexes for scope_statistics
CREATE INDEX `IDX_scope_statistics_user_scope_event_date` ON `scope_statistics` (`userId`, `scope`, `eventType`, `eventDate`);
CREATE INDEX `IDX_scope_statistics_event_date` ON `scope_statistics` (`eventDate`);
CREATE INDEX `IDX_scope_statistics_user_id` ON `scope_statistics` (`userId`);

-- Create client_statistics table
CREATE TABLE `client_statistics` (
    `id` int NOT NULL AUTO_INCREMENT,
    `userId` int NOT NULL,
    `clientId` int NOT NULL,
    `clientName` varchar(255) NOT NULL,
    `eventDate` date NOT NULL,
    `tokensIssued` int NOT NULL DEFAULT 0,
    `tokensActive` int NOT NULL DEFAULT 0,
    `tokensExpired` int NOT NULL DEFAULT 0,
    `tokensRevoked` int NOT NULL DEFAULT 0,
    `createdAt` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (`id`)
) ENGINE=InnoDB;

-- Create indexes for client_statistics
CREATE INDEX `IDX_client_statistics_user_client_date` ON `client_statistics` (`userId`, `clientId`, `eventDate`);
CREATE INDEX `IDX_client_statistics_event_date` ON `client_statistics` (`eventDate`);
CREATE INDEX `IDX_client_statistics_user_id` ON `client_statistics` (`userId`);
CREATE INDEX `IDX_client_statistics_client_id` ON `client_statistics` (`clientId`);

-- Rollback section (for manual rollback if needed)
-- DROP TABLE `client_statistics`;
-- DROP TABLE `scope_statistics`;
-- DROP TABLE `token_statistics`;