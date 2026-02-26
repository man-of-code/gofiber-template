## Go Backend Architecture

### 1. High-Level Overview

- **Stack**: Go 1.24, Fiber v2 HTTP framework, GORM + SQLite, `golang-jwt/jwt/v5`, AES‑256‑GCM with HKDF‑derived keys.
- **Pattern**: Layered architecture:
  - `cmd/server`: composition root, wiring, process lifecycle.
  - `internal/config`: configuration from environment.
  - `internal/db`: database opening/tuning.
  - `internal/models`: ORM models.
  - `internal/services`: business logic (auth, tokens, crypto, items).
  - `internal/middleware`: cross‑cutting concerns (security, logging, rate limiting, IP handling).
  - `internal/routes`: HTTP routing and dependency injection into handlers.
  - `internal/handlers`: HTTP handlers which are thin adapters over services.
  - `internal/cache`, `internal/crypto`, `internal/netutil`, `internal/envutil`, `internal/validator`: supporting utilities.
- **Security goals**:
  - Strong authentication and authorization for API clients.
  - Defense‑in‑depth around IP spoofing, token theft, and brute‑force attacks.
  - Encrypted client identifiers and optional payload encryption.
  - Auditability of sensitive actions.

### 2. Process Entry & Composition Root (`cmd/server`)

`cmd/server/main.go` is the entrypoint and performs:

- **Configuration & logging**
  - Loads `*config.Config` via `config.Load()`.
  - Builds a structured `slog.Logger` with level derived from `LOG_LEVEL`.
  - Enforces presence and basic strength of `ENCRYPTION_KEY` and `JWT_SECRET`.

- **Database initialization**
  - Opens SQLite using `db.Open(cfg.DBPath)`, which:
    - Ensures parent directory exists.
    - Configures WAL mode and tuning pragmas for low‑latency reads.
    - Sets modest connection pool limits for concurrency.
  - Runs `AutoMigrate` on `Item`, `Client`, `Token`, and `AuditLog`.
  - Executes a one‑time, best‑effort migration to backfill `client_id_hash` for existing `tokens` records.

- **Crypto and secrets**
  - Constructs `CryptoService` via `services.NewCryptoService()`:
    - Uses HKDF with a fixed application salt to derive separate keys for:
      - Client ID at rest (`ContextClientAtRest`).
      - Token at rest (`ContextTokenAtRest` – reserved for future use).
      - Payload transport (`ContextPayloadTransport`).
  - After initialization, clears sensitive environment variables:
    - `ENCRYPTION_KEY`, `JWT_SECRET`, `ADMIN_MASTER_KEY`.

- **Services and caches**
  - `AuthService` (client registration/validation).
  - `TokenService` (JWT issuance, refresh, revocation, cleanup).
  - `ItemsService` (CRUD for example domain model).
  - `TokenBlacklist` (in‑memory JTI blacklist).
  - `AuditLogger` (async security audit logging).
  - Background goroutine to periodically invoke `TokenService.CleanupExpired()` to prune revoked tokens.

- **Fiber application**
  - Configured with:
    - Tight read/write/idle timeouts to defend against Slowloris‑style attacks.
    - Bounded `BodyLimit` from config.
    - Concurrency limit and memory‑friendly options for production.
    - Custom `ErrorHandler` for consistent JSON error envelopes.

- **Middleware chain**
  - In order:
    1. `RealIP(cfg)`: derive canonical client IP once, with trusted proxy validation.
    2. `RequestID(cfg)`: propagate/generate `X-Request-ID`.
    3. `RequestLogger(logger)`: structured request logs.
    4. `SecurityHeaders()`: strong HTTP security headers.
    5. `GlobalRateLimit(cfg)`: per‑IP global rate limiting.
    6. `IPValidator(cfg)`: optional IP allow/deny lists.
    7. `PayloadCrypto(cryptoService, cfg.RequireEncryptedPayload)`: request body decryption + enforcement.
    8. `EncryptResponse(cryptoService)`: symmetric encryption for responses when request was encrypted.
    9. `auditLogger.Middleware()`: async, batched audit logging.
  - Finally, `routes.Register` attaches all route groups using constructed dependencies.

### 3. Configuration (`internal/config`)

`Config` centralizes application settings:

- Database & server:
  - `DBPath`, `Port`, `Environment`, `LogLevel`, `BodyLimit`.
- Secrets and tokens:
  - `AdminMasterKey` (admin API key; used by `AdminAuth`).
  - `JWTSecret` (HMAC secret; min length enforced).
  - `AccessTokenTTL`, `RefreshTokenTTL`.
  - `EncryptionKey` (master key for HKDF; hex‑encoded 32 bytes).
- Rate limiting:
  - `GlobalRateLimit`: per‑IP global requests/min.
  - `AuthRateLimit`: per‑IP auth requests/min (token endpoints).
  - `APIRateLimit`: per‑client‑id API requests/min (requires JWT).
- IP / network:
  - `IPMode`: `"whitelist"`, `"blacklist"`, or `"off"`.
  - `TrustedProxies`: CIDR ranges for proxies whose XFF headers are allowed.
  - `GlobalAllowedIPs`, `GlobalBlockedIPs`: global IP ACLs.
  - `TrustedProxyDepth`: how many XFF hops to trust.
- Security flags:
  - `TokenBindingMode`: `"strict"`, `"subnet"`, `"off"` for binding validation.
  - `RequireEncryptedPayload`: when `true`, mutating requests must be encrypted.

Environment variables are parsed once in `Load()`. Comma‑separated lists are normalized via `parseCommaList`.

### 4. Database Layer (`internal/db` & `internal/models`)

#### 4.1 DB opening and tuning

`db.Open(path string)`:

- Creates parent directory for the DB file.
- Constructs a DSN that enables:
  - WAL journal mode for concurrent reads.
  - NORMAL synchronous mode.
  - Increased cache size and in‑memory temp store.
  - Busy timeout and mmap for better throughput.
- Configures connection pool (max open/idle conns, connection lifetime).

#### 4.2 Models

- `Client`:
  - `ClientIDHash` – SHA‑256 of client_id, used for lookups.
  - `ClientIDEnc` – AES‑GCM encrypted client_id string.
  - `SecretHash` – bcrypt of the randomly generated client secret.
  - `AllowedIPs` – JSON array of CIDR strings.
  - `Status` – `active`, `suspended`, `revoked` (enforced by service).
  - Soft deletes via `gorm.DeletedAt`.

- `Token`:
  - `JTI` – unique JWT ID.
  - `ClientIDHash` – SHA‑256 of client_id for grouping and revoke‑all.
  - `ClientDBID` – FK into `clients.id`.
  - `RefreshTokenHash` – SHA‑256 of refresh token (no plaintext storage).
  - IP, UserAgent, issued/expiry timestamps.
  - Revocation fields: `Revoked`, `RevokedAt`, `RevokedReason`.

- `Item`:
  - Simple example domain model with soft deletes.

- `AuditLog`:
  - Stores `RequestID`, action name, a hashed client identifier, IP, UserAgent, and JSON detail payload.

### 5. Services Layer (`internal/services`)

#### 5.1 AuthService

Responsibilities:

- Registering new API clients with one‑time credentials.
- Validating client credentials.
- Managing client metadata and lifecycle (list, get, update, delete).
- Tracking auth failures and auto‑suspending clients under brute‑force.

Key behavior:

- **Client registration**:
  - Generate `client_id` (UUID) and random `secretSize` bytes for secret.
  - Store:
    - `ClientIDHash` = SHA‑256 of `client_id`.
    - `ClientIDEnc` = AES‑GCM encrypted `client_id` via `CryptoService`.
    - `SecretHash` = bcrypt hash of secret bytes.
    - `AllowedIPs` as JSON array.
  - Return plaintext client_id + client_secret once.

- **Credential validation**:
  - Look up by `ClientIDHash`.
  - Normalize timing:
    - Dummy bcrypt compares on not‑found and invalid secret formats.
    - Always run `CompareHashAndPassword` even for suspended clients.
  - Use in‑memory `failureTracker` to count failures per client hash:
    - After threshold, auto‑update status to `suspended` and log a warning.

- **Admin client views**:
  - For list/get, decrypt `ClientIDEnc` back to plaintext.
  - Parse `AllowedIPs` using `netutil.ParseAllowedIPs`.
  - Use `ClientView` projections for handlers, not raw models.

#### 5.2 TokenService

Responsibilities:

- Issuing JWT access + refresh token pairs.
- Refreshing tokens and detecting refresh token reuse.
- Revoking tokens (individual and per client).
- Parsing and validating JWTs for middleware.
- Enforcing IP and fingerprint binding (token binding).
- Cleaning up expired/revoked token rows.

Key points:

- **Token generation**:
  - `generateTokenPair` creates:
    - Unique JTI (UUID).
    - Random refresh token bytes -> SHA‑256 hash stored.
    - JWT with:
      - Subject = client_id (plaintext).
      - Issuer = `gofiber-template`.
      - Audience = `gofiber-template-api`.
      - Custom claims: IP, scope, fingerprint.
    - DB record in `tokens` table keyed by JTI and refresh hash.

- **IssueToken**:
  - Validates credentials via `AuthService`.
  - Checks caller IP against client’s `AllowedIPs` using `netutil.IPInRanges`.
  - Delegates to `generateTokenPair`.

- **RefreshToken**:
  - Looks up token by hashed refresh token.
  - If token already revoked:
    - Best‑effort bulk revoke all tokens for same `ClientIDHash` with reason `refresh_reuse`.
    - Load all revoked JTIs into in‑memory blacklist.
    - Returns `ErrRefreshReuse` to the caller regardless of DB bulk update success.
  - If refresh expired: `ErrTokenExpired`.
  - Validates incoming IP is within current allowed ranges or matches original IP.
  - Inside a transaction:
    - Revokes old token with reason `rotated`, adds JTI to blacklist.
    - Issues a new token pair for same client.

- **RevokeToken**:
  - If a body token is supplied, treats it as refresh token and revokes associated JTI.
  - Otherwise parses the `Authorization` header JWT, then revokes by JTI.
  - Always updates blacklist to enforce immediate blocking.

- **RevokeAllForClient**:
  - Bulk‑updates all non‑revoked tokens for a given `client_db_id`.
  - Returns an error if the bulk update fails.
  - Adds all affected JTIs to the blacklist.

- **CleanupExpired**:
  - Runs periodically to delete old, already‑revoked tokens:
    - Uses batched deletes (`LIMIT 500`) to avoid long‑running transactions.
    - Logs errors via `slog` and stops on first failure.

- **JWT parsing & binding**:
  - `parseAndValidateJWT`:
    - Requires configured `JWTSecret`.
    - Uses `jwt.ParseWithClaims` with explicit `Issuer` and `Audience` constraints.
    - Rejects any token in the blacklist.
  - `ParseJWT` – parses without binding checks.
  - `ParseAndValidateJWT` – optional IP binding.
  - `ValidateBinding`/`validateBinding`:
    - Enforces IP equality (`strict`) or same subnet (`subnet`) via `sameSubnet`.
    - Validates fingerprint (SHA‑256 of client_id | IP | UA) if present.

#### 5.3 CryptoService

Responsibilities:

- Key derivation and symmetric encryption/decryption.
- Dedicated methods for:
  - Client ID at rest.
  - Payloads in transit.

Implementation details:

- Uses `crypto.MasterKey()` to load master key from env and validate size.
- Derives per‑use keys via HKDF contexts, with a fixed application salt.
- AES‑256‑GCM implementation in `internal/crypto/aes.go`:
  - Nonce is generated per operation.
  - Ciphertext format: `nonce || ciphertext+tag`.

#### 5.4 ItemsService

Responsibilities:

- Simple CRUD abstraction for `Item` with pagination.
- **Important**: decouples handlers from GORM, exposing:
  - `ErrItemNotFound` for resource‑not‑found semantics.

Methods:

- `List(page, limit)` – returns `PaginatedItems`.
- `Get(id)` – returns `Item` or `ErrItemNotFound`.
- `Create(name)` – inserts and returns new item.
- `Update(id, name)` – updates an item or returns `ErrItemNotFound`.
- `Delete(id)` – soft‑deletes or returns `ErrItemNotFound`.

#### 5.5 Service Interfaces (`interfaces.go`)

To improve testability and decouple handlers/middleware from concrete services, the following interfaces are defined:

- `TokenValidator`: `ParseJWT`, `ValidateBinding`.
- `TokenIssuer`: issue/refresh/revoke tokens, revoke all for client.
- `ClientManager`: register/validate/list/get/update/delete clients.
- `PayloadCryptor`: encrypt/decrypt payloads and client IDs.

The `routes.Dependencies` struct and handlers/middleware are wired against these interfaces.

### 6. Middleware (`internal/middleware`)

Core middleware responsibilities:

- **RealIP**:
  - Calls `netutil.GetClientIP(c.IP(), XFF, trustedProxies, depth)` once.
  - Stores result in `Locals("real_ip")`.
  - `ClientIP(c)` helper uses this value or falls back to `c.IP()`.

- **RequestID**:
  - Optionally trusts `X-Request-ID` only if the incoming connection is from a trusted proxy (based on XFF last hop).
  - Generates a new UUID otherwise.
  - Propagates as header and `Locals("request_id")`.

- **RequestLogger**:
  - Structured logging with method/path/status/latency/client_id/ip.
  - Handles Fiber errors to ensure consistent status code logging.

- **ErrorHandler**:
  - Converts:
    - `validator.Errors` into `400` with `errors` array.
    - `*fiber.Error` into appropriate status code with message.
    - All other errors into `500` with generic message.
  - Logs unexpected errors with request context and IP.

- **SecurityHeaders**:
  - Adds a strong baseline of security headers (CSP, HSTS, X‑Frame‑Options, etc.).

- **Rate limiting**:
  - `RateLimiter`:
    - Sliding‑window per key with in‑memory maps.
    - Banned set for repeated abuse (temporary ban).
    - Cap on entries (`maxRateLimiterEntries`) to avoid unbounded memory growth.
  - `GlobalRateLimit(cfg)` – per‑IP global limit.
  - `AuthRateLimit(cfg)` – per‑IP auth routes (used by `/auth` and `/admin`).
  - `APIRateLimit(cfg)` – per client_id (extracted from JWT claims) for `/api`.
  - All emit `X-RateLimit-*` headers and `Retry-After` on `429`.

- **IPValidator**:
  - Optional global IP whitelist/blacklist based on `IPMode`.
  - Uses pre‑parsed `net.IPNet` slices.
  - Marks blocked requests to aid audit logging.

- **JWTAuth / TokenBinding**:
  - `JWTAuth`:
    - Validates bearer token in `Authorization`.
    - Stores JWT claims and client_id in `Locals`.
  - `TokenBinding`:
    - Uses `TokenValidator.ValidateBinding` to enforce IP/fingerprint binding.
    - Unauthorized on binding failure.

- **PayloadCrypto / EncryptResponse**:
  - `PayloadCrypto`:
    - When `X-Encrypted-Payload: true`, expects hex‑encoded ciphertext body.
    - Decrypts and replaces request body with plaintext JSON.
    - When `RequireEncryptedPayload` is true, enforces encryption for mutating methods with non‑empty bodies.
  - `EncryptResponse`:
    - If request was encrypted, encrypts response body symmetrically and sets `Content-Type: application/octet-stream`.

- **AdminAuth**:
  - Validates `X-Admin-Key` against `AdminMasterKey` with constant‑time comparison based on hashing.
  - Returns `503` if admin not configured, `401` on invalid/missing key.

- **AuditLogger middleware**:
  - Asynchronously buffers `AuditLog` entries and flushes on ticker or shutdown.
  - Captures high‑value security and mutation events:
    - Token issuance/refresh/revoke.
    - Client create/update/delete/revoke-all.
    - Items create/update/delete.
    - Rate limit exceeded and IP‑blocked events.
  - Stores a hashed client identifier instead of plaintext.

### 7. Routing & Handlers (`internal/routes`, `internal/handlers`)

#### 7.1 Route groups

- `/health`:
  - Public health check, no auth.

- `/auth`:
  - Grouped with `AuthRateLimit` to limit brute‑force.
  - Endpoints:
    - `POST /auth/token`: issue JWT pair.
    - `POST /auth/token/refresh`: rotate refresh tokens.
    - `POST /auth/token/revoke`: revoke by access or refresh token (protected by JWT + binding).

- `/admin`:
  - Grouped with:
    - `AuthRateLimit` – aggressive rate limiting per IP.
    - `AdminAuth` – X‑Admin‑Key based authentication.
  - Endpoints:
    - `POST /admin/clients`: register client.
    - `POST /admin/clients/:id/revoke-all`: revoke all tokens for client.
    - `GET /admin/clients`: list clients.
    - `GET /admin/clients/:id`: get one client.
    - `PUT /admin/clients/:id`: update client.
    - `DELETE /admin/clients/:id`: delete client (+ revoke tokens).

- `/api`:
  - Grouped with:
    - `JWTAuth` – authentication.
    - `TokenBinding` – IP/fingerprint binding.
    - `APIRateLimit` – per client_id throttling.
  - Example resource: `/api/items` with full CRUD and pagination.

#### 7.2 Handlers

- `AuthHandler`:
  - Thin adapter around `ClientManager` and `TokenIssuer`.
  - Performs input validation using `validator` helpers.
  - Converts service‑level errors into appropriate HTTP statuses without leaking sensitive information.

- `ItemsHandler`:
  - Uses `ItemsService` and `validator` for pagination and input validation.
  - Distinguishes not‑found vs other errors using `services.ErrItemNotFound`.

- `Health`:
  - Returns `{"status": "ok"}` for simple liveness checks.

### 8. Cross-Cutting Concerns & Security Mapping

This backend maps directly to many of the "Top 100 Web Vulnerabilities" mitigation controls:

- **Injection**:
  - Use of GORM and parameterized query APIs for DB access.
  - No string‑built SQL in this code.

- **Authentication & Session**:
  - JWT with HMAC (`JWTSecret`), with issuer/audience validation.
  - Refresh token rotation and reuse detection with bulk revoke.
  - Admin key protected via constant‑time comparison.
  - Rate limiting on auth and admin endpoints.

- **Data Exposure**:
  - Client IDs encrypted at rest.
  - No plaintext refresh tokens or secrets stored.
  - Audit log stores hashed client identifier instead of plaintext.

- **Security Misconfiguration**:
  - Strong default security headers.
  - Configurable IP ACLs and trusted proxy lists.
  - Payload encryption enforcement optional but available.

- **DoS / Abuse**:
  - Global, auth, and API rate limiting with bans on abuse.
  - Tight Fiber timeouts and body limits.
  - Bounded in‑memory structures for rate limiting and blacklist.

### 9. Operational Considerations

- **Configuration**:
  - Secrets must be supplied via environment (.env, Kubernetes secrets, etc.).
  - Trusted proxies and IP ACLs must reflect actual deployment topology to avoid IP spoofing.

- **Startup & Shutdown**:
  - On startup, revoked tokens are loaded into in‑memory blacklist.
  - Background token cleanup and audit logger batching continue for process lifetime.
  - On shutdown:
    - `AuditLogger.Shutdown()` flushes pending entries.
    - `app.Shutdown()` stops handling new requests.

- **Testing**:
  - Unit and benchmark tests exist for:
    - Crypto performance and correctness.
    - DB operations with SQLite.
    - Token issuance/refresh/revocation flows.
    - netutil IP parsing and XFF behavior.
    - Middleware behavior (rate limiting, admin auth, RealIP).

This document should be the starting point for any future refactors: when changing behavior, update the corresponding section so that architecture and implementation stay aligned. 

