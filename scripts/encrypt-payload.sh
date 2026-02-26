#!/usr/bin/env bash
# Encrypt payload using ENCRYPTION_KEY from .env
# Usage: ./scripts/encrypt-payload.sh [payload]
#   With arg: encrypts the given string
#   Without arg: reads from stdin
# Output: hex-encoded ciphertext for X-Encrypted-Payload requests

set -e
cd "$(dirname "$0")/.."
go run ./cmd/encrypt-payload "$@"
