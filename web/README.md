# React API Test Client

This app is a development test client for the GoFiber API in this repository.

## Features

- Tabs for `Health`, `Admin`, `Auth`, and `Items`
- Right-side network inspector with expandable request details
- Default dark UI for API debugging
- Optional payload encryption using the same AES-256-GCM scheme as the Go server

## Encryption Alignment

When request encryption is enabled:

- Browser derives the payload transport key from `VITE_ENCRYPTION_KEY` using HKDF-SHA256
- HKDF salt: `VITE_APP_ID` (default `gofiber_template`); **must match the server’s `APP_ID`** or decryption will fail
- HKDF info/context: `payload-transport`
- Payload format: `hex(nonce(12B) || ciphertext+tag)`
- Header `X-Encrypted-Payload: true` is sent for encrypted requests

This matches backend behavior in:

- `internal/crypto/keys.go`
- `internal/crypto/aes.go`
- `internal/middleware/payload_crypto.go`

## Setup

1. Install dependencies:

```bash
cd web
npm install
```

2. Create `web/.env.local` with required values:

```bash
# web/.env.local
# Required: must match Go server .env
VITE_ENCRYPTION_KEY=<same value as ENCRYPTION_KEY>
VITE_ADMIN_KEY=<same value as ADMIN_MASTER_KEY>

# Required for encrypted payloads: must match server APP_ID (default gofiber_template)
VITE_APP_ID=gofiber_template
```

3. Run servers:

```bash
# terminal 1
go run ./cmd/server

# terminal 2
cd web
npm run dev
```

Open [http://localhost:5173](http://localhost:5173).

## Important Security Note

This browser client is a PoC tool. Putting `VITE_ENCRYPTION_KEY` in frontend code means users can extract it, so this is not production-grade end-to-end confidentiality. Keep this pattern for local/dev tooling, not internet-facing production clients.
