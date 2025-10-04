#!/bin/bash

# RSA Key Pair Generation Script
# Generates RSA key pair in environment variable format for console output.

set -e

echo "Generating RSA key pair..."

# Temporary files
PRIVATE_KEY_FILE="private.pem"
PUBLIC_KEY_FILE="public.pem"

# Generate RSA private key (2048 bits)
openssl genrsa -out "$PRIVATE_KEY_FILE" 2048

# Extract public key
openssl rsa -in "$PRIVATE_KEY_FILE" -pubout -out "$PUBLIC_KEY_FILE"

echo "Key generation completed!"
echo ""

# Output in environment variable format (convert newlines to \n)
echo "# RSA key pair for environment variables:"
printf "RSA_PRIVATE_KEY=\""
awk '{printf "%s\\n", $0}' "$PRIVATE_KEY_FILE" | sed 's/\\n$//'
printf "\"\n"
echo ""
printf "RSA_PUBLIC_KEY=\""
awk '{printf "%s\\n", $0}' "$PUBLIC_KEY_FILE" | sed 's/\\n$//'
printf "\"\n"
echo ""

# Clean up temporary files
rm -f "$PRIVATE_KEY_FILE" "$PUBLIC_KEY_FILE"

echo "Script execution completed. Copy the environment variable values above to your .env file."