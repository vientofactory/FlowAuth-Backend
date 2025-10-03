#!/bin/bash

# Migration Script: Add OIDC Support
# This script adds OIDC support to the database by:
# - Adding nonce and authTime columns to authorization_code table
# - Initializing OIDC scopes (openid, identify, email)
# Run this script after deploying the OIDC implementation

set -e  # Exit on any error

# Configuration
DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-3306}"
DB_NAME="${DB_NAME:-flowauth}"
DB_USER="${DB_USER:-root}"
DB_PASS="${DB_PASS:-}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}     OIDC Support Migration Script     ${NC}"
echo -e "${BLUE}========================================${NC}"

# Check if mysql client is available
if ! command -v mysql &> /dev/null; then
    echo -e "${RED}Error: mysql client is not installed or not in PATH${NC}"
    exit 1
fi

# Test database connection
echo -e "${YELLOW}Testing database connection...${NC}"
if ! mysql -h"$DB_HOST" -P"$DB_PORT" -u"$DB_USER" -p"$DB_PASS" -e "SELECT 1;" "$DB_NAME" &> /dev/null; then
    echo -e "${RED}Error: Cannot connect to database${NC}"
    echo -e "${RED}Please check your database credentials and ensure the database is running${NC}"
    exit 1
fi
echo -e "${GREEN}Database connection successful${NC}"

# Show current state before migration
echo -e "${BLUE}Checking current database state...${NC}"
mysql -h"$DB_HOST" -P"$DB_PORT" -u"$DB_USER" -p"$DB_PASS" "$DB_NAME" << 'EOF'
SELECT 'CURRENT STATE - Authorization Code table structure:' as info;
DESCRIBE authorization_code;

SELECT 'CURRENT STATE - Existing OIDC scopes:' as info;
SELECT id, name, description, isActive
FROM scope
WHERE name IN ('openid', 'identify', 'email')
ORDER BY name;

SELECT 'CURRENT STATE - Sample authorization codes:' as info;
SELECT id, code, scopes, expiresAt, isUsed
FROM authorization_code
ORDER BY createdAt DESC
LIMIT 3;
EOF

echo ""
echo -e "${YELLOW}⚠️  IMPORTANT: This migration will add OIDC support to your database.${NC}"
echo -e "${YELLOW}   It will add 'nonce' and 'authTime' columns to authorization_code table${NC}"
echo -e "${YELLOW}   and initialize OIDC scopes. Make sure you have a backup before proceeding.${NC}"
echo ""
read -p "Do you want to continue? (y/N): " -n 1 -r
echo ""
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${BLUE}Migration cancelled by user${NC}"
    exit 0
fi

# Run the migration
echo -e "${BLUE}Running OIDC support migration...${NC}"
mysql -h"$DB_HOST" -P"$DB_PORT" -u"$DB_USER" -p"$DB_PASS" "$DB_NAME" < "$(dirname "$0")/add_oidc_support.sql"

echo -e "${GREEN}Migration completed successfully!${NC}"

# Show final verification
echo -e "${BLUE}Final verification...${NC}"
mysql -h"$DB_HOST" -P"$DB_PORT" -u"$DB_USER" -p"$DB_PASS" "$DB_NAME" << 'EOF'
SELECT 'AFTER MIGRATION - Authorization Code table structure:' as verification;
DESCRIBE authorization_code;

SELECT 'AFTER MIGRATION - OIDC scopes verification:' as verification;
SELECT id, name, description, isActive
FROM scope
WHERE name IN ('openid', 'identify', 'email')
ORDER BY name;

SELECT 'AFTER MIGRATION - Column existence check:' as verification;
SELECT 'nonce column exists:' as check_type,
       COUNT(*) > 0 as exists_flag
FROM information_schema.COLUMNS
WHERE TABLE_SCHEMA = DATABASE()
  AND TABLE_NAME = 'authorization_code'
  AND COLUMN_NAME = 'nonce'

UNION ALL

SELECT 'authTime column exists:' as check_type,
       COUNT(*) > 0 as exists_flag
FROM information_schema.COLUMNS
WHERE TABLE_SCHEMA = DATABASE()
  AND TABLE_NAME = 'authorization_code'
  AND COLUMN_NAME = 'authTime'

UNION ALL

SELECT 'nonce index exists:' as check_type,
       COUNT(*) > 0 as exists_flag
FROM information_schema.STATISTICS
WHERE TABLE_SCHEMA = DATABASE()
  AND TABLE_NAME = 'authorization_code'
  AND INDEX_NAME = 'idx_authorization_code_nonce';
EOF

echo ""
echo -e "${GREEN}✅ OIDC Support Migration completed successfully!${NC}"
echo -e "${GREEN}   Your database now supports OIDC authentication flows.${NC}"
echo -e "${BLUE}   OIDC scopes: openid, identify, email are now available.${NC}"