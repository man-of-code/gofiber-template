## gofiber_template

`gofiber_template` is a hardened GoFiber webserver template using [Fiber](https://gofiber.io/) and [GORM](https://gorm.io/) with SQLite. It includes client credentials, JWT auth, AES-256-GCM payload encryption, and layered security middleware (rate limiting, IP validation, token binding, and security headers).

### Getting Started

#### Prerequisites

- Go 1.24+ installed
- (Optional) SQLite CLI if you want to inspect the database file

#### Clone and setup

```bash
git clone <your-repo-url> gofiber_template
cd gofiber_template

# Optionally rename the top-level directory if you cloned under a different name
# mv hanushield_demo gofiber_template
```

#### Environment file

```bash
cp .env.example .env
```

You can either edit `.env` manually or use the env key generator:

```bash
# Generate strong secrets for ENCRYPTION_KEY, JWT_SECRET, ADMIN_MASTER_KEY
go run ./cmd/genenv
```

Copy the generated values into `.env` or use the generator's interactive mode (once implemented) to create/overwrite `.env` for you.

#### Run the server

```bash
go run ./cmd/server
```

The server listens on `http://localhost:3000` by default.

Hit the health endpoint to verify:

```bash
curl http://localhost:3000/health
```

### Environment Variables

| Variable  | Required | Description |
|-----------|----------|-------------|
| `ENCRYPTION_KEY` | Yes | 32 bytes hex-encoded (64 chars) for AES-256-GCM (normally generated via `go run ./cmd/genenv`) |
| `JWT_SECRET` | Yes | At least 64 bytes of entropy (hex or base64) for HMAC-SHA256 signing (normally generated via `go run ./cmd/genenv`) |
| `ADMIN_MASTER_KEY` | Yes | High-entropy key for the `X-Admin-Key` header on admin endpoints (normally generated via `go run ./cmd/genenv`) |
| `PORT` | No | HTTP listen port, default `3000` |
| `DB_PATH` | No | SQLite database path, default `./data/app.db` |
| `ENV` | No | `dev` or `prod`, affects logging and some safety defaults |
| `LOG_LEVEL` | No | `debug`, `info`, `warn`, `error` (default `info`) |
| `ACCESS_TOKEN_TTL` | No | Access token TTL, default `15m` |
| `REFRESH_TOKEN_TTL` | No | Refresh token TTL, default `24h` |
| `GLOBAL_RATE_LIMIT` | No | Global requests per window |
| `AUTH_RATE_LIMIT` | No | Auth endpoints requests per window |
| `API_RATE_LIMIT` | No | Authenticated API requests per window |
| `IP_MODE` | No | IP validation mode (`off`, etc.) |
| `TOKEN_BINDING_MODE` | No | Token binding mode (`strict`, `subnet`, `off`) |

### Security Model Overview

`gofiber_template` is designed as a secure starting point for GoFiber APIs:

- **AES-256-GCM payload encryption**: Request/response bodies can be encrypted with a 32-byte symmetric key (`ENCRYPTION_KEY`).
- **JWT-based authentication**: Access and refresh tokens with configurable TTLs and HMAC-SHA256 signing (`JWT_SECRET`).
- **Client credentials & admin key**: Client registration via admin endpoints, protected by an `X-Admin-Key` header (`ADMIN_MASTER_KEY`).
- **Defense-in-depth middleware**: Request ID, structured logging, rate limiting, IP validation, token binding, security headers, and body size limits.

For full details, see `docs/security/security-spec.md`.
