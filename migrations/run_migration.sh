#!/bin/bash

# Migration Script: Remove Legacy OAuth2 Scopes
# This script safely removes 'basic', 'read:user', 'read:profile' scopes from the database
# Run this script after deploying the code changes that remove legacy scope support

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
echo -e "${BLUE} OAuth2 Legacy Scopes Removal Migration ${NC}"
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

# Backup warning
echo -e "${YELLOW}⚠️  IMPORTANT: This migration will permanently remove legacy OAuth2 scopes${NC}"
echo -e "${YELLOW}   from your database. Make sure you have a backup before proceeding.${NC}"
echo ""
read -p "Do you want to continue? (y/N): " -n 1 -r
echo ""
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${BLUE}Migration cancelled by user${NC}"
    exit 0
fi

# Show current state before migration
echo -e "${BLUE}Checking current state before migration...${NC}"
mysql -h"$DB_HOST" -P"$DB_PORT" -u"$DB_USER" -p"$DB_PASS" "$DB_NAME" << 'EOF'
SELECT 'BEFORE MIGRATION - Clients with legacy scopes:' as info;
SELECT id, clientId, name, scopes
FROM client
WHERE scopes IS NOT NULL
  AND (JSON_CONTAINS(scopes, JSON_QUOTE('basic'))
       OR JSON_CONTAINS(scopes, JSON_QUOTE('read:user'))
       OR JSON_CONTAINS(scopes, JSON_QUOTE('read:profile')));

SELECT 'BEFORE MIGRATION - Tokens with legacy scopes:' as info;
SELECT id, tokenType, scopes, isRevoked
FROM token
WHERE scopes IS NOT NULL
  AND (JSON_CONTAINS(scopes, JSON_QUOTE('basic'))
       OR JSON_CONTAINS(scopes, JSON_QUOTE('read:user'))
       OR JSON_CONTAINS(scopes, JSON_QUOTE('read:profile')));

SELECT 'BEFORE MIGRATION - Auth codes with legacy scopes:' as info;
SELECT id, code, scopes, isUsed
FROM authorization_code
WHERE scopes IS NOT NULL
  AND (JSON_CONTAINS(scopes, JSON_QUOTE('basic'))
       OR JSON_CONTAINS(scopes, JSON_QUOTE('read:user'))
       OR JSON_CONTAINS(scopes, JSON_QUOTE('read:profile')));
EOF

echo ""
read -p "Proceed with migration? (y/N): " -n 1 -r
echo ""
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${BLUE}Migration cancelled by user${NC}"
    exit 0
fi

# Run the migration
echo -e "${BLUE}Running migration...${NC}"
mysql -h"$DB_HOST" -P"$DB_PORT" -u"$DB_USER" -p"$DB_PASS" "$DB_NAME" < "$(dirname "$0")/remove_legacy_oauth2_scopes.sql"

echo -e "${GREEN}Migration completed successfully!${NC}"

# Show final verification
echo -e "${BLUE}Final verification...${NC}"
mysql -h"$DB_HOST" -P"$DB_PORT" -u"$DB_USER" -p"$DB_PASS" "$DB_NAME" << 'EOF'
SELECT 'AFTER MIGRATION - Verification (should all be 0):' as verification;
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
EOF

echo ""
echo -e "${GREEN}✅ Migration completed successfully!${NC}"
echo -e "${GREEN}   Legacy OAuth2 scopes have been removed from your database.${NC}"
echo -e "${BLUE}   Your OAuth2 system now only uses 'identify' and 'email' scopes.${NC}"