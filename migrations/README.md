# OIDC Support Migration

## Overview

This migration adds OpenID Connect (OIDC) support to the database by adding required fields to the `authorization_code` table and initializing OIDC scopes.

## Background

The OAuth2 system has been enhanced with OIDC capabilities to support modern identity federation. The following OIDC features have been implemented:

- **Implicit Grant Flow**: Direct token issuance without authorization code exchange
- **ID Tokens**: JWT-based identity tokens with user claims
- **Nonce Support**: CSRF protection for authorization requests
- **Authentication Time**: Timestamp tracking for user authentication
- **OIDC Scopes**: `openid`, `identify`, `email` scope support

## Database Changes

### Authorization Code Table

New columns added to `authorization_code` table:

- `nonce` (VARCHAR(128) NULL): Stores the nonce parameter for CSRF protection
- `authTime` (BIGINT NULL): Stores authentication timestamp in Unix epoch milliseconds

### Scope Table

New OIDC scopes initialized:

- `openid`: Required for OIDC compliance
- `identify`: User identity information (name, profile)
- `email`: User email address access

## Migration Files

### 1. `add_oidc_support.sql`

The main migration script that:

- Adds `nonce` and `authTime` columns to `authorization_code` table
- Creates indexes for performance optimization
- Initializes OIDC scopes in the `scope` table
- Provides verification queries

### 2. `dry_run_legacy_scopes.sql`

A read-only preview script that shows:

- Current authorization code table structure
- Existing scope definitions
- What changes will be made
- No data is modified

### 3. `run_migration.sh`

An interactive bash script that:

- Tests database connectivity
- Shows current database state
- Runs the migration with user confirmation
- Provides final verification

## Safety Features

- **Backup Required**: Always backup your database before running
- **Dry Run First**: Run `dry_run_legacy_scopes.sql` to see current state
- **Interactive Confirmation**: The bash script requires user confirmation
- **Verification**: Multiple verification queries ensure successful migration
- **Idempotent**: Safe to run multiple times (uses `IF NOT EXISTS` and `INSERT IGNORE`)

## How to Run

### Option 1: Using the Interactive Script (Recommended)

```bash
cd backend/migrations
chmod +x run_migration.sh
./run_migration.sh
```

### Option 2: Manual Execution

```bash
# 1. First, run dry run to see current state
mysql -u username -p database_name < dry_run_legacy_scopes.sql

# 2. If satisfied, run the actual migration
mysql -u username -p database_name < add_oidc_support.sql
```

## Expected Results

After successful migration:

- `authorization_code` table should have `nonce` and `authTime` columns
- Index `idx_authorization_code_nonce` should exist
- OIDC scopes (`openid`, `identify`, `email`) should be present in `scope` table
- All verification queries should confirm successful schema changes

## Rollback

To rollback this migration:

1. Drop the added columns:

```sql
ALTER TABLE authorization_code DROP COLUMN nonce;
ALTER TABLE authorization_code DROP COLUMN authTime;
```

2. Remove OIDC scopes (if not used):

```sql
DELETE FROM scope WHERE name IN ('openid', 'identify', 'email');
```

⚠️ **Note**: Only rollback if OIDC features are not being used, as existing authorization codes may reference the new columns.

## Testing

After migration, test:

1. OIDC Implicit Grant flow works correctly
2. Authorization codes store nonce and authTime values
3. ID tokens are generated with correct claims
4. OIDC scopes are available in client configurations
5. Existing OAuth2 flows continue to work

## Version Info

- Migration Date: 2025-01-15
- Compatible with: FlowAuth v2.0.0+
- Requires: MySQL 5.7.8+ (JSON functions support)

## Safety Features

- **Backup Required**: Always backup your database before running
- **Dry Run First**: Run `dry_run_legacy_scopes.sql` to see what will change
- **Interactive Confirmation**: The bash script requires user confirmation
- **Verification**: Multiple verification queries ensure complete removal

## How to Run

### Option 1: Using the Interactive Script (Recommended)

```bash
cd backend/migrations
chmod +x run_migration.sh
./run_migration.sh
```

### Option 2: Manual Execution

```bash
# 1. First, run dry run to see what will change
mysql -u username -p database_name < dry_run_legacy_scopes.sql

# 2. If satisfied, run the actual migration
mysql -u username -p database_name < remove_legacy_oauth2_scopes.sql
```

## Expected Results

After successful migration:

- No records should contain `basic`, `read:user`, or `read:profile` scopes
- Valid scopes (`identify`, `email`) should remain intact
- Empty scope arrays should be cleaned up (set to NULL)
- All verification queries should return 0 for legacy scope counts

## Rollback

⚠️ **This migration is not easily reversible.** If you need to rollback:

1. Restore from database backup taken before migration
2. Revert the code changes that removed legacy scope support

## Testing

After migration, test:

1. OAuth2 authorization flows work with `identify` and `email` scopes
2. Existing tokens with valid scopes continue to work
3. New client registrations only get valid scopes
4. OAuth tester generates correct URLs

## Version Info

- Migration Date: 2025-09-28
- Compatible with: FlowAuth v1.5.0+
- Requires: MySQL 5.7.8+ (JSON functions support)
