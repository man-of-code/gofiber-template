# Code Review & Security Spec Verification Report

**Date:** 2026-02-27  
**Scope:** Codebase vs. [gofiber-template-code-review.md](../plans/gofiber-template-code-review.md) and [security-spec.md](../security/security-spec.md)

---

## 1. Code Review Findings — Status

### Critical (🔴)

| # | Finding | Status | Evidence |
|---|---------|--------|----------|
| 1 | IPValidator bypasses Fiber's native proxy check | **FIXED** | `internal/middleware/ipvalidator.go` uses `ClientIP(c)` (line 24) as the single canonical source. |
| 2 | DeleteClient not atomic (TOCTOU) | **FIXED** | `internal/handlers/auth.go` wraps `RevokeAllForClientTx` + `DeleteClientTx` in `h.DB.Transaction()` (lines 272–281). Interfaces expose `RevokeAllForClientTx(tx, id)` and `DeleteClientTx(tx, id)`. |
| 3 | `errors.Is` not used for GORM sentinel errors | **FIXED** | `auth_service.go` and `token_service.go` use `errors.Is(err, gorm.ErrRecordNotFound)`; `items_service.go` same. |
| 4 | requestIDFromTrustedProxy conflates two conditions | **FIXED** | `internal/middleware/request_id.go`: checks `len(trusted)==0` first, then X-Request-ID, then direct IP in trusted set (lines 33–50). |

### New (Docs) (🆕)

| # | Finding | Status | Evidence |
|---|---------|--------|----------|
| A | c.Locals type assertion `!ok` branch silently bypasses auth | **FIXED** | `internal/middleware/token_binding.go`: on `!ok` returns `fiber.NewError(fiber.StatusUnauthorized, "unauthorized")` (lines 17–20). |
| B | SetBodyStream not correct Fiber v2 body replacement API | **FIXED** | `internal/middleware/payload_crypto.go` uses `c.Request().SetBody(pt)` and `SetContentTypeBytes([]byte(...))` (lines 37–38). |

### Design (🟠)

| # | Finding | Status | Evidence |
|---|---------|--------|----------|
| 5 | failureTracker unbounded memory growth | **FIXED** | `auth_service.go`: `maxFailureTrackerEntries = 10000`, `evictStaleLocked`, cap check before insert, background sweep goroutine (lines 23, 61–93, 110–116). |
| 6 | Hardcoded appSalt couples forks to same key domain | **FIXED** | `internal/crypto/keys.go`: `deriveKey(master, appID, context)` with configurable `appID`; `config.Config.AppID` from `APP_ID`; main.go requires `APP_ID` at startup. |
| 7 | genenv weaker ADMIN_MASTER_KEY without explanation | **FIXED** | `cmd/genenv/main.go`: `adminKey, err := randomHex(32)` with comment "256-bit: consistent with ENCRYPTION_KEY"; validate expects 64 hex chars (32 bytes). |
| 8 | Rate limiter goroutines never stopped | **FIXED** | `internal/middleware/ratelimit.go`: `stop chan struct{}`, select in goroutine, `Stop()` method (lines 22, 46–56, 61–67). Tests call `defer rl.Stop()`. |
| 9 | ListClients full table scan, no pagination | **FIXED** | `AuthService.ListClients(page, limit int)` with Count, Limit, Offset; handler uses `ParsePagination` and returns `meta.page`, `meta.total`, etc. |
| 10 | One-time migration error silently discarded | **FIXED** | `cmd/server/main.go`: migration error logged with `slog.Warn("one-time token migration failed — ...", "error", err)` (lines 43–45). |

### Quality (🟡)

| # | Finding | Status | Evidence |
|---|---------|--------|----------|
| 11 | Item.Name no max length validation or DB constraint | **FIXED** | `models/item.go`: `Name string gorm:"size:255"`. `handlers/items.go` Create/Update: `len(strings.TrimSpace(req.Name)) > 255` + errs.Add (lines 70–72, 101–103). |
| 12 | sync.RWMutex used as write-only lock | **FIXED** | `ratelimit.go`: type is `sync.Mutex` (line 15). |
| 13 | Cleanup test asserts nothing meaningful | **FIXED** | `ratelimit_test.go`: backdates entries to `oldTS`, calls cleanup, asserts `len(rl.entries) == 0`; uses `defer rl.Stop()` (lines 165–184). |
| 14 | AuditLog.ClientID field name misleading | **FIXED** | `models/audit_log.go`: field `ClientIDHash` with `gorm:"column:client_id;index;size:64"` and comment; `middleware/audit.go` sets `ClientIDHash`. |
| 15 | Missing defer f.Close() in envutil.Load() | **FIXED** | `internal/envutil/loadenv.go`: `defer f.Close()` inside IIFE wrapping the scan loop (lines 19–37). |
| 16 | No handler-level integration tests | **FIXED** | `internal/handlers/auth_integration_test.go`: `setupTestApp`, `registerTestClient`, full request path via `app.Test(req)`. |

### Optional / Not Applied

- **Finding #1 Option B:** Fiber’s `EnableTrustedProxyCheck`, `TrustedProxies`, `ProxyHeader` in `fiber.Config` are **not** set. The review’s Option A (use `ClientIP(c)` in IPValidator) is implemented; Option B would allow removing the custom RealIP middleware. Current design is consistent (RealIP → ClientIP everywhere).

---

## 2. Security Spec — Implementation Verification

### 2.1 Authentication & Credential Security (§2)

| Spec requirement | Implemented | Location / notes |
|------------------|-------------|------------------|
| Client credentials issued by admin endpoint, master key protected | Yes | Admin routes use X-Admin-Key; config.AdminMasterKey. |
| client_id UUID v4, crypto/rand | Yes | auth_service.go: uuid.New().String(), secretBytes from rand.Read. |
| client_secret 64 bytes crypto/rand, hex, shown once | Yes | secretSize 64, hashed with bcrypt before storage. |
| bcrypt cost 12 | Yes | bcryptCost = 12 in auth_service.go. |
| Client ID encrypted at rest AES-256-GCM, derived key | Yes | CryptoService, HKDF client-at-rest context. |
| No default credentials, CSPRNG only | Yes | No defaults; crypto/rand used. |
| Auth flow: rate limit → lookup → status → AllowedIPs → bcrypt → issue tokens | Yes | TokenService.IssueToken + AuthService.ValidateCredentials; IP check, failure tracking. |
| Brute-force: 10 req/min auth, 5 failures → 10 min ban, 10 failures → suspend | Yes | AuthRateLimit(cfg), failureTracker (limit 10, window 5 min), evict + sweep. |
| Constant-time: no timing difference not-found vs wrong secret | Yes | Dummy bcrypt compare on not-found/invalid paths. |

### 2.2 Token Security (§3)

| Spec requirement | Implemented | Location / notes |
|------------------|-------------|------------------|
| JWT: HS256, short TTL 15 min, ip+fingerprint in claims, JTI | Yes | token_service: HMAC-SHA256, AccessTokenTTL, claims include ip, fp, jti. |
| Refresh: 64 bytes rand, SHA-256 in DB, 24h TTL, single-use, IP bound | Yes | Refresh token generation, hash storage, RefreshToken rotation. |
| Rotation in transaction, revoke old then issue new | Yes | RefreshToken uses DB transaction; RevokeAllForClientTx exists. |
| Reuse detection: revoke all client tokens, log CRITICAL, 401 | Yes | Refresh token reuse path revokes all for client, logged. |
| Revocation: explicit, rotation, client revoke, expiry, in-memory blacklist | Yes | RevokeToken, blacklist with TTL eviction, startup load from DB. |

### 2.3 Encryption Architecture (§4)

| Spec requirement | Implemented | Location / notes |
|------------------|-------------|------------------|
| Client ID at rest: AES-256-GCM, HKDF client-at-rest | Yes | crypto/keys.go, CryptoService. |
| Token metadata at rest: AES-256-GCM, HKDF token-at-rest | Yes | Same. |
| Payload transport: optional AES-256-GCM, HKDF payload-transport | Yes | PayloadCrypto middleware, CryptoService. |
| Key hierarchy: ENCRYPTION_KEY → HKDF(salt=app_id, info=context) | Yes | deriveKey(master, appID, context); AppID required. |
| Master key from env, unset after load | Yes | main.go: os.Unsetenv for ENCRYPTION_KEY, JWT_SECRET, ADMIN_MASTER_KEY. |

### 2.4 IP Validation & Network (§5)

| Spec requirement | Implemented | Location / notes |
|------------------|-------------|------------------|
| Global allow/block lists, CIDR parsing at startup | Yes | IPValidator, netutil.ParseCIDRs. |
| Auth: request IP vs client AllowedIPs | Yes | TokenService / ValidateCredentials IP check. |
| JWT: request IP vs token ip claim | Yes | TokenBinding + ValidateBinding. |
| X-Forwarded-For with trusted proxy depth | Yes | RealIP middleware, netutil.GetClientIP, TrustedProxies in config. |
| requestIDFromTrustedProxy: only trust ID when from trusted proxy IP | Yes | request_id.go checks direct IP in trusted set. |

### 2.5 Anti-Impostor (§6)

| Spec requirement | Implemented | Location / notes |
|------------------|-------------|------------------|
| Token-IP binding (strict/subnet/off) | Yes | TokenBinding middleware, ValidateBinding; TokenBindingMode in config. |
| Fingerprint SHA256(client_id+IP+User-Agent) in JWT | Yes | Claims and validation in token_service. |
| Constant-time comparisons (subtle.ConstantTimeCompare, bcrypt) | Yes | Used for token/hash comparison; dummy bcrypt for not-found. |

### 2.6 DDoS & Abuse (§7)

| Spec requirement | Implemented | Location / notes |
|------------------|-------------|------------------|
| Global per-IP, auth per-IP, API per-client limits | Yes | GlobalRateLimit, AuthRateLimit, APIRateLimit; config values. |
| 429 + Retry-After | Yes | ratelimit middleware sets Retry-After. |
| Auto-blacklist (e.g. 5× limit → 10 min ban) | Yes | banLimit, banDur, banned map in RateLimiter. |
| ReadTimeout 5s, WriteTimeout 10s | Yes | main.go fiber.Config. |
| IdleTimeout | Partial | Spec: 120s. Code: 30s (main.go). **Recommend aligning to 120s if spec is authoritative.** |
| BodyLimit 1MB, header limits | Yes | BodyLimit from config; Fiber defaults for headers. |

### 2.7 Input Validation & Injection (§8)

| Spec requirement | Implemented | Location / notes |
|------------------|-------------|------------------|
| GORM parameterized queries, no raw SQL for user input | Yes | GORM query builder; migration Exec is fixed DDL. |
| Path params positive integer | Yes | validator.ParsePositiveUint. |
| name non-empty, max 255, trimmed | Yes | items handler Create/Update. |
| client_id UUID v4, client_secret 128 hex | Yes | Validated in auth flow / token service. |
| Pagination page/limit validated | Yes | validator.ParsePagination. |
| API-only, JSON, no HTML/XSS surface | Yes | JSON responses, security headers. |
| No user-controlled outbound requests (SSRF) | Yes | No such flow in codebase. |

### 2.8 Information Disclosure (§9)

| Spec requirement | Implemented | Location / notes |
|------------------|-------------|------------------|
| Sanitized error responses (generic 500/401/404/400/429) | Yes | ErrorHandler and handler-level returns. |
| Security headers (HSTS, CSP, X-Frame-Options, nosniff, etc.) | Yes | security_headers.go. |
| Account enumeration prevention (same response, constant-time) | Yes | Uniform 401, dummy bcrypt. |

### 2.9 Session & State (§10)

| Spec requirement | Implemented | Location / notes |
|------------------|-------------|------------------|
| Stateless JWT, revocation via blacklist | Yes | JWT validation + blacklist. |
| Tokens in Authorization: Bearer only, not in URL | Yes | Handlers and middleware use header. |

### 2.10 Cryptographic Standards (§11)

| Spec requirement | Implemented | Location / notes |
|------------------|-------------|------------------|
| AES-256-GCM, 96-bit random nonce | Yes | crypto/aead usage. |
| bcrypt cost 12, HMAC-SHA256 JWT, HKDF-SHA256, crypto/rand | Yes | As above. |

### 2.11 Audit & Monitoring (§12)

| Spec requirement | Implemented | Location / notes |
|------------------|-------------|------------------|
| Audited events (client_created, token_issued, auth_failed, impostor_detected, etc.) | Yes | audit.go action mapping and AuditLog model. |
| Structured logging, no secrets in logs | Yes | log/slog; no tokens/secrets in responses or logs. |
| AuditLog persisted to DB | Yes | AuditLogger with batch insert. |

### 2.12 Security Configuration Checklist (§15)

| Item | Status | Notes |
|------|--------|--------|
| ENCRYPTION_KEY 32 bytes hex | Enforced | main.go + genenv. |
| JWT_SECRET min 64 bytes | Enforced | main.go len check; genenv 64 bytes. |
| ADMIN_MASTER_KEY | Enforced | genenv 32 bytes (64 hex chars); spec checklist says "64 random bytes" (128 hex) — **implementation uses 32 bytes (256-bit)**; code review recommended 32 bytes. |
| APP_ID / key separation | Enforced | main.go requires APP_ID. |
| TrustedProxies | Config | From env; not passed to Fiber’s native proxy (see Finding #1 Option B). |
| Rate limits, BodyLimit, timeouts | Yes | As above. |
| Secrets cleared from env after load | Yes | main.go Unsetenv. |

---

## 3. Summary

- **Code review:** All 16 findings from the code review document are **fixed** in the codebase. Option B for Finding #1 (Fiber native proxy config) is not applied; Option A is.
- **Security spec:** All major security measures described in the security spec are **implemented**. Exceptions:
  - **IdleTimeout:** Spec 120s, code 30s — consider increasing if spec is desired.
  - **ADMIN_MASTER_KEY length:** Spec checklist and key commands say 64 bytes (128 hex); implementation and genenv use 32 bytes (64 hex). Align spec or implementation if 64-byte admin key is required.

### Recommendation

1. Align **IdleTimeout** with the security spec (e.g. 120s) or update the spec to 30s with rationale.
2. Align **ADMIN_MASTER_KEY** documentation: either update the security spec to 32 bytes (256-bit) to match implementation, or change genenv/validation to 64 bytes if 64-byte admin key is required.
