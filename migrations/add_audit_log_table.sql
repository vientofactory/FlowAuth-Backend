-- Migration: AddAuditLogTable1760000000000
-- Description: Creates the audit_log table and its foreign key constraints
-- Date: 2025-10-25

USE flowauth;

-- Create audit_log table
CREATE TABLE IF NOT EXISTS `audit_log` (
  `id` int NOT NULL AUTO_INCREMENT,
  `eventType` varchar(50) NOT NULL,
  `severity` varchar(20) NOT NULL DEFAULT 'low',
  `description` text NOT NULL,
  `metadata` json NULL,
  `ipAddress` varchar(45) NULL,
  `userAgent` varchar(500) NULL,
  `httpMethod` varchar(10) NULL,
  `endpoint` varchar(500) NULL,
  `responseStatus` int NULL,
  `userId` int NULL,
  `clientId` int NULL,
  `resourceId` int NULL,
  `resourceType` varchar(100) NULL,
  `createdAt` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  INDEX `IDX_audit_log_user_created` (`userId`, `createdAt`),
  INDEX `IDX_audit_log_client_created` (`clientId`, `createdAt`),
  INDEX `IDX_audit_log_event_created` (`eventType`, `createdAt`),
  INDEX `IDX_audit_log_severity_created` (`severity`, `createdAt`),
  INDEX `IDX_audit_log_ip` (`ipAddress`),
  PRIMARY KEY (`id`)
) ENGINE=InnoDB;

-- Add foreign key constraints
ALTER TABLE `audit_log`
ADD CONSTRAINT `FK_audit_log_user`
FOREIGN KEY (`userId`) REFERENCES `user`(`id`) ON DELETE SET NULL ON UPDATE NO ACTION;

ALTER TABLE `audit_log`
ADD CONSTRAINT `FK_audit_log_client`
FOREIGN KEY (`clientId`) REFERENCES `client`(`id`) ON DELETE SET NULL ON UPDATE NO ACTION;

-- Record the migration as executed (if using manual migration tracking)
-- INSERT INTO `migrations` (`timestamp`, `name`) VALUES (1760000000000, 'AddAuditLogTable1760000000000');