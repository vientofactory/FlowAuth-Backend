#!/bin/bash

# RSA Key Pair Generation Script
# Generates RSA key pair and optionally saves to files or outputs in environment variable format.

set -e

# Default values
OUTPUT_DIR="./keys"
SAVE_TO_FILES=false
OUTPUT_ENV_VARS=true

# Parse command line arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --save-files)
      SAVE_TO_FILES=true
      shift
      ;;
    --output-dir)
      OUTPUT_DIR="$2"
      shift
      shift
      ;;
    --env-only)
      OUTPUT_ENV_VARS=true
      SAVE_TO_FILES=false
      shift
      ;;
    --help|-h)
      echo "Usage: $0 [OPTIONS]"
      echo ""
      echo "Options:"
      echo "  --save-files     Save keys to files in ./keys directory"
      echo "  --output-dir DIR Specify output directory for key files (default: ./keys)"
      echo "  --env-only       Only output environment variables (default behavior)"
      echo "  --help, -h       Show this help message"
      echo ""
      echo "Examples:"
      echo "  $0                          # Output environment variables only"
      echo "  $0 --save-files             # Save to files and output env vars"
      echo "  $0 --save-files --output-dir ./config/keys  # Save to custom directory"
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      echo "Use --help for usage information."
      exit 1
      ;;
  esac
done

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

# Save to files if requested
if [[ "$SAVE_TO_FILES" == "true" ]]; then
  mkdir -p "$OUTPUT_DIR"
  cp "$PRIVATE_KEY_FILE" "$OUTPUT_DIR/private.pem"
  cp "$PUBLIC_KEY_FILE" "$OUTPUT_DIR/public.pem"
  echo "Keys saved to files:"
  echo "  Private key: $OUTPUT_DIR/private.pem"
  echo "  Public key:  $OUTPUT_DIR/public.pem"
  echo ""

  # Output environment variables for file paths
  echo "# Environment variables for file-based configuration:"
  echo "RSA_PRIVATE_KEY_FILE=\"$OUTPUT_DIR/private.pem\""
  echo "RSA_PUBLIC_KEY_FILE=\"$OUTPUT_DIR/public.pem\""
  echo ""
fi

# Output in environment variable format if requested
if [[ "$OUTPUT_ENV_VARS" == "true" ]]; then
  echo "# RSA key pair for environment variables:"
  printf "RSA_PRIVATE_KEY=\""
  awk '{printf "%s\\n", $0}' "$PRIVATE_KEY_FILE" | sed 's/\\n$//'
  printf "\"\n"
  echo ""
  printf "RSA_PUBLIC_KEY=\""
  awk '{printf "%s\\n", $0}' "$PUBLIC_KEY_FILE" | sed 's/\\n$//'
  printf "\"\n"
  echo ""
fi

# Clean up temporary files
rm -f "$PRIVATE_KEY_FILE" "$PUBLIC_KEY_FILE"

echo "Script execution completed."
if [[ "$SAVE_TO_FILES" == "true" ]]; then
  echo "Copy the environment variable values above to your .env file."
  echo "Or use the file paths if you prefer file-based configuration."
else
  echo "Copy the environment variable values above to your .env file."
fi