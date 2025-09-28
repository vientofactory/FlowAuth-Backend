# OAuth2 Legacy Scopes Removal Migration

## Overview

This migration removes legacy OAuth2 scopes (`basic`, `read:user`, `read:profile`) from the database after simplifying the OAuth2 scope system to only use `identify` and `email` scopes.

## Background

The OAuth2 scope system was recently simplified to reduce complexity and improve user experience. The following changes were made to the codebase:

- Removed `BASIC` scope from SDK enum
- Updated default scopes to only include `IDENTIFY`
- Removed legacy scope references from frontend OAuth tester
- Updated API documentation examples

## Affected Tables

- `client.scopes` (JSON array)
- `token.scopes` (JSON array)
- `authorization_code.scopes` (JSON array)

## Migration Files

### 1. `remove_legacy_oauth2_scopes.sql`

The main migration script that:

- Identifies records containing legacy scopes
- Removes `basic`, `read:user`, and `read:profile` from scope arrays
- Cleans up empty scope arrays
- Provides verification queries

### 2. `dry_run_legacy_scopes.sql`

A read-only preview script that shows:

- Which records would be affected
- What the scopes would look like after removal
- Summary statistics
- No data is modified

### 3. `run_migration.sh`

An interactive bash script that:

- Tests database connectivity
- Shows before/after previews
- Runs the migration with user confirmation
- Provides final verification

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
