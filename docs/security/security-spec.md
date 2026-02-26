# Security Specification

**Date:** 2026-02-26
**Version:** 1.0
**Classification:** Internal — Engineering

---

## Table of Contents

1. [Threat Model](#1-threat-model)
2. [Authentication & Credential Security](#2-authentication--credential-security)
3. [Token Security](#3-token-security)
4. [Encryption Architecture](#4-encryption-architecture)
5. [IP Validation & Network Security](#5-ip-validation--network-security)
6. [Anti-Impostor Measures](#6-anti-impostor-measures)
7. [DDoS & Abuse Prevention](#7-ddos--abuse-prevention)
8. [Input Validation & Injection Prevention](#8-input-validation--injection-prevention)
9. [Information Disclosure Prevention](#9-information-disclosure-prevention)
10. [Session & State Security](#10-session--state-security)
11. [Cryptographic Standards](#11-cryptographic-standards)
12. [Audit & Monitoring](#12-audit--monitoring)
13. [OWASP Top 10 Mapping](#13-owasp-top-10-mapping)
14. [Vulnerability Coverage Matrix](#14-vulnerability-coverage-matrix)
15. [Security Configuration Checklist](#15-security-configuration-checklist)

---

## 1. Threat Model

### 1.1 Assets

| Asset                                         | Sensitivity | Location                                    |
| --------------------------------------------- | ----------- | ------------------------------------------- |
| Client credentials (client_id, client_secret) | Critical    | DB (encrypted at rest), transit (encrypted) |
| JWT access tokens                             | High        | Client memory, HTTP headers                 |
| Refresh tokens                                | Critical    | Client memory, DB (hashed)                  |
| Encryption master key                         | Critical    | Environment variable (never in code/DB)     |
| JWT signing secret                            | Critical    | Environment variable                        |
| Item data                                     | Medium      | DB                                          |
| Audit logs                                    | Medium      | DB                                          |

### 1.2 Threat Actors

| Actor             | Capability                      | Motivation                     |
| ----------------- | ------------------------------- | ------------------------------ |
| External attacker | Network access, automated tools | Data theft, service disruption |
| Credential thief  | Stolen client_id/secret         | Unauthorized API access        |
| Token thief       | Intercepted JWT                 | Impersonation, data access     |
| Insider threat    | Partial system access           | Data exfiltration              |
| DDoS operator     | Botnet, amplification           | Service denial                 |

### 1.3 Attack Surfaces

```
Internet → [Rate Limiter] → [IP Validator] → [TLS termination*]
  → [Payload Decryption] → [JWT Validation] → [Token Binding]
  → [Input Validation] → [Handler] → [DB]

* TLS handled by reverse proxy in production
```

---

## 2. Authentication & Credential Security

### 2.1 Client Registration

**Vulnerability addressed:** Weak Authentication Mechanisms (OWASP A07), Default Passwords (#28), Credential Stuffing (#22)

**Implementation:**

- Client credentials are issued by an admin endpoint protected by a master key
- `client_id`: UUID v4 (128-bit entropy, cryptographically random via `crypto/rand`)
- `client_secret`: 64 bytes from `crypto/rand` (512-bit entropy), hex-encoded for transport
- Secret is displayed exactly once at registration; it is never stored in plaintext
- Secret is hashed with bcrypt (cost factor 12, ~10ms verification) before storage
- ClientID is encrypted at rest with AES-256-GCM using a derived key

**Why bcrypt:** Resistant to GPU/ASIC acceleration, adaptive cost factor, built-in salt. At cost 12, brute-forcing a 64-byte secret is computationally infeasible.

**Controls:**

- No default credentials ever exist in the system
- Credential generation uses only `crypto/rand` (CSPRNG), never `math/rand`
- Client secrets cannot be retrieved after registration — only re-issued
- Suspended/revoked clients cannot authenticate

### 2.2 Client Authentication Flow

**Vulnerability addressed:** Brute Force (#15), Credential Stuffing (#22), Insufficient Authentication

```
Client                          Server
  │                                │
  │  POST /auth/token              │
  │  {client_id, client_secret}    │
  │ ──────────────────────────────>│
  │                                │ 1. Rate limit check (10 req/min per IP)
  │                                │ 2. Lookup client by client_id
  │                                │ 3. Verify client status == active
  │                                │ 4. Verify IP in client's AllowedIPs
  │                                │ 5. bcrypt.Compare(secret, stored_hash)
  │                                │ 6. Issue JWT access + refresh token
  │                                │ 7. Persist token metadata (JTI, IP, timestamp)
  │                                │ 8. Audit log: token_issued
  │                                │
  │  {access_token, refresh_token, │
  │   expires_in, token_type}      │
  │ <──────────────────────────────│
```

**Brute-force mitigations:**

- Auth endpoints rate-limited to 10 requests/minute per IP
- After 5 consecutive failed attempts from an IP: temporary 10-minute IP ban
- After 10 consecutive failed attempts for a client_id: client auto-suspended, admin alert
- bcrypt's inherent slowness (~10ms/attempt) makes high-volume brute force impractical
- No timing difference between "client not found" and "wrong secret" responses (constant-time comparison)

---

## 3. Token Security

### 3.1 JWT Access Token

**Vulnerability addressed:** Session Hijacking (#16), Insufficient Session Management (#72), Insecure Token Storage

**Structure:**

```json
{
  "header": {
    "alg": "HS256",
    "typ": "JWT"
  },
  "payload": {
    "sub": "<client_id>",
    "jti": "<uuid_v4>",
    "iat": 1709000000,
    "exp": 1709000900,
    "ip": "192.168.1.1",
    "fp": "<fingerprint_hash>",
    "scope": "api"
  }
}
```

**Security properties:**

- Short TTL: 15 minutes (limits window of compromise)
- Signed with HMAC-SHA256 using 64-byte secret (prevents tampering)
- Contains bound IP address (prevents token theft from different network)
- Contains client fingerprint hash (additional binding)
- Contains unique JTI for revocation tracking
- No sensitive data in claims (no secret, no PII beyond client_id)

### 3.2 Refresh Token

**Vulnerability addressed:** Session Fixation (#14), Insufficient Token Expiration

- 64 bytes from `crypto/rand`, hex-encoded
- Stored as SHA-256 hash in database (never in plaintext)
- TTL: 24 hours
- Single-use: consumed on rotation, new pair issued
- Bound to original IP address

### 3.3 Token Rotation

**Vulnerability addressed:** Token Replay, Session Fixation (#14), Privilege Persistence

```
Client                          Server
  │                                │
  │  POST /auth/token/refresh      │
  │  {refresh_token}               │
  │ ──────────────────────────────>│
  │                                │ 1. Hash refresh_token → lookup in DB
  │                                │ 2. Verify not revoked, not expired
  │                                │ 3. Verify request IP matches token IP
  │                                │ 4. BEGIN TRANSACTION
  │                                │    a. Revoke old access + refresh token
  │                                │    b. Issue new access + refresh token
  │                                │    c. Persist new token metadata
  │                                │ 5. COMMIT
  │                                │ 6. Audit log: token_rotated
  │                                │
  │  {new_access_token,            │
  │   new_refresh_token, ...}      │
  │ <──────────────────────────────│
```

**Refresh token reuse detection (critical):**
If a refresh token that was already consumed is presented again, it indicates token theft. The server immediately:

1. Revokes ALL active tokens for that client
2. Logs a security alert with full context (IP, user-agent, timestamp)
3. Returns 401 (does not reveal the reason to the attacker)

This is based on the principle that in normal operation, a refresh token is used exactly once. Any reuse means either the legitimate client or an attacker has a stale token.

### 3.4 Token Invalidation

**Vulnerability addressed:** Insufficient Session Termination, Token Persistence After Logout

**Mechanisms:**

1. **Explicit revocation:** `POST /auth/token/revoke` marks token as revoked in DB
2. **Rotation revocation:** Old tokens revoked during refresh
3. **Client revocation:** Admin can revoke all tokens for a client
4. **Expiry:** Tokens naturally expire (access: 15m, refresh: 24h)
5. **In-memory blacklist:** Revoked JTIs cached in `sync.Map` for O(1) middleware checks

**Performance consideration:**
The in-memory blacklist avoids a DB query on every request. Entries are auto-evicted when the original token would have expired (max 15 minutes for access tokens), keeping memory bounded.

On server restart, non-expired revoked JTIs are loaded from DB into memory.

---

## 4. Encryption Architecture

### 4.1 Encryption At Rest

**Vulnerability addressed:** Unencrypted Data Storage (#25), Data Leakage (#24)

| Data                  | Algorithm                     | Key                                       |
| --------------------- | ----------------------------- | ----------------------------------------- |
| Client ID (DB column) | AES-256-GCM                   | Derived: `HKDF(master, "client-at-rest")` |
| Token metadata        | AES-256-GCM                   | Derived: `HKDF(master, "token-at-rest")`  |
| Client secret         | bcrypt (hash, not encryption) | N/A — one-way                             |
| Refresh token (DB)    | SHA-256 (hash)                | N/A — one-way                             |

### 4.2 Encryption In Transit

**Vulnerability addressed:** Man-in-the-Middle (#52), Insufficient Transport Layer Security (#53)

**Payload encryption layer (application-level):**

- Clients may encrypt request bodies with AES-256-GCM using a shared transport key
- Header `X-Encrypted-Payload: true` signals encrypted body
- Server middleware decrypts before handler processing
- If request was encrypted, response is encrypted symmetrically
- Transport key derived from master: `HKDF(master, "payload-transport")`

**Network-level (production):**

- TLS 1.2+ required (terminated at reverse proxy)
- HSTS header with `max-age=31536000; includeSubDomains`
- Forward secrecy via ECDHE cipher suites

### 4.3 Key Management

**Vulnerability addressed:** Insecure Key Storage, Key Compromise

**Key hierarchy:**

```
ENCRYPTION_KEY (master, 32 bytes, hex in env var)
  │
  ├─ HKDF(master, salt=app_id, info="client-at-rest")   → client_key
  ├─ HKDF(master, salt=app_id, info="token-at-rest")    → token_key
  └─ HKDF(master, salt=app_id, info="payload-transport") → transport_key

JWT_SECRET (separate, 64 bytes, hex in env var)
```

**Key rotation protocol:**

1. Generate new master key, set as `ENCRYPTION_KEY_NEW` in env
2. Application enters dual-key mode: decrypt with old or new, encrypt with new
3. Background job re-encrypts all at-rest data with new key
4. Remove old key, rename new to `ENCRYPTION_KEY`

**Controls:**

- Master key never stored in code, config files, or database
- Master key loaded from environment variable at startup, zeroed from env after read
- Derived keys held in memory only, never serialized
- No key material in logs, error messages, or API responses

### 4.4 Cryptographic Specifications

| Purpose              | Algorithm   | Key Size       | Nonce             | Tag     |
| -------------------- | ----------- | -------------- | ----------------- | ------- |
| Symmetric encryption | AES-256-GCM | 256-bit        | 96-bit random     | 128-bit |
| Password hashing     | bcrypt      | N/A            | Built-in salt     | N/A     |
| Token hashing        | SHA-256     | N/A            | N/A               | N/A     |
| JWT signing          | HMAC-SHA256 | 512-bit        | N/A               | N/A     |
| Key derivation       | HKDF-SHA256 | 256-bit output | App-specific salt | N/A     |
| Random generation    | crypto/rand | N/A            | N/A               | N/A     |

---

## 5. IP Validation & Network Security

### 5.1 IP Validation Middleware

**Vulnerability addressed:** Unauthorized Access, Unrestricted Network Access (#31)

**Layers of IP validation:**

| Layer             | Check                                          | Fail Action      |
| ----------------- | ---------------------------------------------- | ---------------- |
| Global middleware | IP against global allow/block lists            | 403 Forbidden    |
| Auth endpoint     | Request IP against client's `AllowedIPs` CIDRs | 403 Forbidden    |
| JWT middleware    | Request IP against token's `ip` claim          | 401 Unauthorized |

**Implementation details:**

- CIDR parsing at startup into `net.IPNet` objects (no per-request parsing overhead)
- Support IPv4 and IPv6
- `X-Forwarded-For` / `X-Real-IP` parsing with configurable trusted proxy depth
- Only the rightmost untrusted IP is used (prevents header spoofing)

### 5.2 Proxy Trust Model

**Vulnerability addressed:** IP Spoofing via Header Injection (#67)

```
Client → Proxy1 → Proxy2 → Application

X-Forwarded-For: client_ip, proxy1_ip

Trusted proxies: [proxy2_ip]
Extracted client IP: client_ip (skip 1 trusted proxy from right)
```

**Controls:**

- `TrustedProxies` is an explicit allowlist (no wildcard)
- If no trusted proxies configured, `c.IP()` returns direct connection IP
- `X-Forwarded-For` header only parsed if request comes from a trusted proxy IP
- Rejects requests with malformed IP headers

---

## 6. Anti-Impostor Measures

### 6.1 Token-IP Binding

**Vulnerability addressed:** Session Hijacking (#16), Token Theft, Man-in-the-Middle (#52)

Every JWT contains the IP address it was issued to. On each request:

```
if token.ip != request.ip AND request.ip NOT IN client.AllowedIPs:
    → 401 Unauthorized
    → Audit: impostor_detected (token JTI, expected IP, actual IP)
    → Auto-revoke token
```

**Strictness modes:**

- `strict`: Exact IP match required
- `subnet`: Same /24 (IPv4) or /48 (IPv6) allowed (for mobile/NAT)
- `off`: No IP binding (not recommended)

### 6.2 Client Fingerprinting

**Vulnerability addressed:** Session Hijacking (#16), Credential Theft

The JWT `fp` claim contains: `SHA256(client_id + IP + User-Agent)`

If the fingerprint doesn't match on a request, the token is rejected. This adds a layer beyond IP alone — an attacker would need to replicate the exact User-Agent string.

### 6.3 Refresh Token Reuse Detection

**Vulnerability addressed:** Token Replay, Stolen Token Exploitation

As described in Section 3.3: reuse of a consumed refresh token triggers immediate revocation of all tokens for the affected client. This is the strongest defense against refresh token theft.

### 6.4 Constant-Time Comparisons

**Vulnerability addressed:** Timing Attacks (#93)

All secret comparisons use constant-time functions:

- `crypto/subtle.ConstantTimeCompare` for token/hash comparisons
- `bcrypt.CompareHashAndPassword` (inherently constant-time)
- Identical error responses for "not found" vs "wrong credentials" (no enumeration)

---

## 7. DDoS & Abuse Prevention

### 7.1 Rate Limiting

**Vulnerability addressed:** DDoS (#61), Application Layer DoS (#62), Brute Force (#15), Resource Exhaustion (#63), API Abuse (#75)

**Rate limit tiers:**

| Scope           | Limit        | Key        | Penalty           |
| --------------- | ------------ | ---------- | ----------------- |
| Global per-IP   | 1000 req/min | IP address | 429 + Retry-After |
| Auth per-IP     | 10 req/min   | IP address | 429 + Retry-After |
| API per-client  | 200 req/min  | client_id  | 429 + Retry-After |
| Burst tolerance | 5x sustained | IP address | 10-min auto-ban   |

**Implementation:** Sliding window counter in memory (`sync.Map` with atomic counters, per-second granularity, 60-second window).

**Why in-memory:** For a single-instance deployment (SQLite constraint), in-memory is the lowest-latency option. For distributed deployments, this would be replaced with Redis.

### 7.2 Slowloris Prevention

**Vulnerability addressed:** Slowloris Attack (#64)

| Parameter      | Value | Purpose                     |
| -------------- | ----- | --------------------------- |
| ReadTimeout    | 5s    | Kill slow request reads     |
| WriteTimeout   | 10s   | Kill slow response writes   |
| IdleTimeout    | 120s  | Reclaim idle connections    |
| ReadBufferSize | 8KB   | Limit per-connection memory |

### 7.3 Request Size Limits

**Vulnerability addressed:** Resource Exhaustion (#63), Buffer Overflow

| Parameter      | Value                |
| -------------- | -------------------- |
| BodyLimit      | 1 MB                 |
| HeaderLimit    | 8 KB (Fiber default) |
| Max URL length | 2048 bytes           |

Oversized requests are rejected with 413 (body) or 431 (headers) before any processing.

### 7.4 Auto-Blacklisting

**Vulnerability addressed:** Persistent Abuse, Botnet Traffic

IPs that exceed 5x the rate limit in a sliding window are automatically blacklisted for 10 minutes. The blacklist is checked at the IP validation layer (before any other processing), making blacklisted requests extremely cheap to reject.

---

## 8. Input Validation & Injection Prevention

### 8.1 SQL Injection Prevention

**Vulnerability addressed:** SQL Injection (#1)

- GORM uses parameterized queries exclusively — user input never concatenated into SQL
- `PrepareStmt: true` in GORM config for prepared statement caching
- No raw SQL queries in the codebase; all DB access through GORM's query builder
- Input validated before reaching the ORM layer

### 8.2 Request Validation

**Vulnerability addressed:** Inadequate Input Validation (#51), Command Injection (#5)

Every handler validates its input before processing:

| Input               | Validation                                          |
| ------------------- | --------------------------------------------------- |
| Path params (`:id`) | Must be positive integer, reject non-numeric        |
| JSON body           | Parsed via `BodyParser`, unknown fields ignored     |
| `name` field        | Non-empty, max 255 chars, trimmed, no control chars |
| `client_id`         | Must match UUID v4 format                           |
| `client_secret`     | Must be 128 hex chars (64 bytes)                    |
| Pagination `page`   | Positive integer, default 1                         |
| Pagination `limit`  | 1–100 integer, default 20                           |
| CIDR in AllowedIPs  | Must parse as valid `net.IPNet`                     |

**Rejected input returns 400 with field-level errors.** Validation errors never include the submitted value (prevents reflection attacks).

### 8.3 XSS Prevention

**Vulnerability addressed:** Cross-Site Scripting (#2), DOM-based XSS (#56)

- API-only server (no HTML rendering) — XSS attack surface is minimal
- All responses are `Content-Type: application/json`
- `X-Content-Type-Options: nosniff` prevents MIME sniffing
- `Content-Security-Policy: default-src 'none'` blocks any script execution
- JSON output is properly escaped by Go's `encoding/json`

### 8.4 SSRF Prevention

**Vulnerability addressed:** SSRF (#66), Blind SSRF (#87)

- The application does not make outbound HTTP requests based on user input
- No URL parameters are accepted that could trigger server-side fetches
- If future features require outbound requests: strict URL allowlisting + no private IP ranges

---

## 9. Information Disclosure Prevention

### 9.1 Error Response Sanitization

**Vulnerability addressed:** Information Disclosure (#33), Stack Trace Exposure

| Scenario         | Internal Log            | Client Response                                      |
| ---------------- | ----------------------- | ---------------------------------------------------- |
| DB error         | Full error + query      | `{"error": "internal server error"}` + 500           |
| Auth failure     | Client ID + IP + reason | `{"error": "unauthorized"}` + 401                    |
| Not found        | Resource type + ID      | `{"error": "not found"}` + 404                       |
| Validation error | Field details           | `{"errors": [{"field": "x", "message": "y"}]}` + 400 |
| Rate limited     | IP + counter            | `{"error": "rate limit exceeded"}` + 429             |

**Principle:** Log everything internally, reveal nothing sensitive externally.

### 9.2 Header Hardening

**Vulnerability addressed:** Server Fingerprinting, Clickjacking (#59), MIME Sniffing (#89)

```
Server: (removed)
X-Powered-By: (removed)
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 0
Content-Security-Policy: default-src 'none'
Strict-Transport-Security: max-age=31536000; includeSubDomains
Cache-Control: no-store
Referrer-Policy: no-referrer
Permissions-Policy: geolocation=(), microphone=(), camera=()
```

### 9.3 Account Enumeration Prevention

**Vulnerability addressed:** Account Enumeration (#96)

- Auth failure for "client not found" returns the same response as "wrong secret"
- Response timing is normalized (bcrypt always runs, even for missing clients, using a dummy hash)
- Rate limiting prevents high-volume enumeration attempts

---

## 10. Session & State Security

### 10.1 Stateless Access Tokens

**Vulnerability addressed:** Session Fixation (#14), Insufficient Session Management

- JWT access tokens are stateless — validated by signature and expiry alone
- No server-side session state for normal request flow
- Revocation checked via lightweight in-memory blacklist (not a full session store)

### 10.2 Secure Token Transport

**Vulnerability addressed:** Insecure Token Transmission (#53), Cookie Security (#85)

- Tokens transmitted in `Authorization: Bearer` header only
- No tokens in URL parameters (prevents logging/caching exposure)
- No cookies used (eliminates CSRF attack surface entirely)
- Clients instructed to store tokens in memory only (not localStorage/sessionStorage)

### 10.3 Token Lifetime Management

| Token Type         | TTL        | Rotation            | Revocation            |
| ------------------ | ---------- | ------------------- | --------------------- |
| Access token       | 15 min     | Via refresh         | Immediate (blacklist) |
| Refresh token      | 24 hours   | Single-use rotation | Immediate (DB)        |
| Client credentials | Indefinite | Manual re-issue     | Admin suspension      |

---

## 11. Cryptographic Standards

### 11.1 Algorithm Selection Rationale

| Algorithm        | Use                  | Why This Choice                                                        |
| ---------------- | -------------------- | ---------------------------------------------------------------------- |
| AES-256-GCM      | Symmetric encryption | NIST-approved, authenticated encryption, hardware-accelerated (AES-NI) |
| bcrypt (cost 12) | Password hashing     | Memory-hard, GPU-resistant, adaptive cost, 10ms target                 |
| HMAC-SHA256      | JWT signing          | Standard for symmetric JWTs, fast, no key management complexity of RSA |
| HKDF-SHA256      | Key derivation       | RFC 5869, extracts entropy from master key with domain separation      |
| SHA-256          | Token hashing        | Preimage-resistant, fast, sufficient for token integrity               |
| crypto/rand      | Random generation    | OS-level CSPRNG (getrandom/urandom), not predictable                   |

### 11.2 What We Do NOT Use (And Why)

| Avoided              | Reason                                                       |
| -------------------- | ------------------------------------------------------------ |
| MD5/SHA1             | Broken collision resistance                                  |
| AES-CBC              | No built-in authentication, padding oracle attacks           |
| `math/rand`          | Predictable, not cryptographically secure                    |
| RSA for JWT          | Unnecessary complexity for single-service deployment         |
| Argon2 for passwords | Not in Go stdlib, bcrypt is sufficient for this threat model |

### 11.3 Nonce Management

- AES-256-GCM nonces: 12 bytes from `crypto/rand`, prepended to ciphertext
- With 96-bit random nonces, collision probability is negligible below 2^32 encryptions per key
- Key rotation (Section 4.3) ensures we never approach this limit

---

## 12. Audit & Monitoring

### 12.1 Audited Events

| Event                       | Logged Fields                       | Severity |
| --------------------------- | ----------------------------------- | -------- |
| `client_created`            | admin_ip, client_name               | INFO     |
| `client_suspended`          | admin_ip, client_id, reason         | WARN     |
| `token_issued`              | client_id, ip, jti                  | INFO     |
| `token_rotated`             | client_id, ip, old_jti, new_jti     | INFO     |
| `token_revoked`             | client_id, ip, jti, reason          | INFO     |
| `auth_failed`               | ip, client_id (if provided), reason | WARN     |
| `impostor_detected`         | jti, expected_ip, actual_ip         | CRITICAL |
| `refresh_reuse_detected`    | client_id, ip, token_hash           | CRITICAL |
| `rate_limit_exceeded`       | ip, endpoint, count                 | WARN     |
| `ip_blocked`                | ip, rule                            | WARN     |
| `auto_blacklisted`          | ip, duration, trigger               | WARN     |
| `client_all_tokens_revoked` | client_id, admin_ip, count          | WARN     |

### 12.2 Log Security

**Vulnerability addressed:** Insufficient Logging (#73)

- Structured JSON logs via `log/slog`
- Sensitive fields NEVER logged: tokens, secrets, encryption keys, request bodies
- Client IDs logged in truncated form: `abc12...f9` (first 5 + last 2 chars)
- Log injection prevention: structured fields prevent format string attacks
- Audit logs persisted to DB (survives log rotation)

### 12.3 Alerting Triggers

| Condition                                       | Action                                 |
| ----------------------------------------------- | -------------------------------------- |
| `impostor_detected`                             | Revoke token, log CRITICAL             |
| `refresh_reuse_detected`                        | Revoke all client tokens, log CRITICAL |
| 10+ `auth_failed` for same client in 5 min      | Suspend client, log CRITICAL           |
| 50+ `rate_limit_exceeded` from same IP in 1 min | Auto-blacklist 10 min                  |

---

## 13. OWASP Top 10 (2021) Mapping

| OWASP Category                     | Server Controls                                                                                                                                       | Section        |
| ---------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- | -------------- |
| **A01: Broken Access Control**     | JWT auth middleware, IP binding, token-IP verification, per-client AllowedIPs, RBAC (admin vs client), function-level access control on all endpoints | §2, §3, §5, §6 |
| **A02: Cryptographic Failures**    | AES-256-GCM at rest, bcrypt for secrets, HMAC-SHA256 JWT, HKDF key derivation, no weak algorithms, TLS 1.2+ in production                             | §4, §11        |
| **A03: Injection**                 | GORM parameterized queries (no raw SQL), strict input validation, no shell execution, no template injection surface                                   | §8             |
| **A04: Insecure Design**           | Threat modeling (§1), defense in depth (8 middleware layers), refresh token reuse detection, constant-time comparisons                                | §1, §6         |
| **A05: Security Misconfiguration** | Security headers middleware, no debug in production, no default credentials, minimal attack surface (API-only), stripped server headers               | §9             |
| **A06: Vulnerable Components**     | Minimal dependencies (4 external), no known vulnerabilities in current versions, dependency pinning in go.mod                                         | §11            |
| **A07: Authentication Failures**   | bcrypt hashing, rate-limited auth, IP validation, MFA-ready architecture, account lockout, anti-enumeration                                           | §2             |
| **A08: Data Integrity Failures**   | JWT signature verification, AES-GCM authenticated encryption (tamper-evident), refresh token hash integrity                                           | §3, §4         |
| **A09: Logging Failures**          | Comprehensive audit trail, structured logging, security event alerting, log injection prevention                                                      | §12            |
| **A10: SSRF**                      | No user-controlled outbound requests, no URL parameters for fetches                                                                                   | §8.4           |

---

## 14. Vulnerability Coverage Matrix

Mapping to the Top 100 Web Vulnerabilities reference:

| #     | Vulnerability                 | Status        | How Addressed                                                       |
| ----- | ----------------------------- | ------------- | ------------------------------------------------------------------- |
| 1     | SQL Injection                 | **Mitigated** | GORM parameterized queries, no raw SQL                              |
| 2     | XSS                           | **Mitigated** | API-only (no HTML), JSON content-type, CSP, nosniff                 |
| 5     | Command Injection             | **Mitigated** | No shell/exec calls, no user input in system commands               |
| 6-8   | XML/LDAP/XPath Injection      | **N/A**       | No XML/LDAP/XPath processing                                        |
| 13    | SSTI                          | **N/A**       | No template engine                                                  |
| 14    | Session Fixation              | **Mitigated** | Stateless JWT, token rotation on refresh                            |
| 15    | Brute Force                   | **Mitigated** | Rate limiting (10/min auth), auto-ban, bcrypt slowness              |
| 16    | Session Hijacking             | **Mitigated** | Token-IP binding, fingerprinting, short TTL, HTTPS                  |
| 22    | Credential Stuffing           | **Mitigated** | Rate limiting, IP validation, client-specific AllowedIPs            |
| 23    | IDOR                          | **Mitigated** | Authorization middleware, scoped queries per client                 |
| 24    | Data Leakage                  | **Mitigated** | Encrypted at rest, sanitized errors, no debug info                  |
| 25    | Unencrypted Storage           | **Mitigated** | AES-256-GCM for sensitive fields, bcrypt for secrets                |
| 26    | Missing Security Headers      | **Mitigated** | Full security header middleware (§9.2)                              |
| 28    | Default Passwords             | **Mitigated** | No defaults, crypto/rand generated credentials                      |
| 29    | Directory Listing             | **N/A**       | API-only, no static file serving                                    |
| 30    | Unprotected API Endpoints     | **Mitigated** | JWT middleware on all /api routes, admin key on /admin              |
| 31    | Open Ports                    | **Mitigated** | Single port, no unnecessary services                                |
| 33    | Information Disclosure        | **Mitigated** | Sanitized errors, stripped headers, no stack traces                 |
| 34    | Unpatched Software            | **Addressed** | Minimal dependencies, go.mod version pinning                        |
| 35    | Misconfigured CORS            | **Mitigated** | No CORS enabled (API-only, same-origin or server-to-server)         |
| 37    | XXE                           | **N/A**       | No XML processing                                                   |
| 40    | Inadequate Authorization      | **Mitigated** | JWT claims + middleware + per-endpoint checks                       |
| 41    | Privilege Escalation          | **Mitigated** | Scoped tokens, admin/client separation, no sudo patterns            |
| 42    | IDOR                          | **Mitigated** | Authorization checks before object access                           |
| 43    | Forceful Browsing             | **Mitigated** | Auth required on all data endpoints                                 |
| 44    | Missing Function-Level Access | **Mitigated** | Server-side middleware, not just client-side                        |
| 45-47 | Insecure Deserialization      | **Mitigated** | JSON only (no binary serialization), strict parsing                 |
| 48    | Insecure API Endpoints        | **Mitigated** | OAuth-style auth, HTTPS, rate limiting                              |
| 49    | API Key Exposure              | **Mitigated** | Keys in env vars only, never in code/logs/responses                 |
| 50    | Lack of Rate Limiting         | **Mitigated** | Multi-tier rate limiting (§7.1)                                     |
| 51    | Inadequate Input Validation   | **Mitigated** | Centralized validation (§8.2)                                       |
| 52    | MITM                          | **Mitigated** | TLS (production), HSTS, payload encryption layer                    |
| 53    | Insufficient TLS              | **Mitigated** | TLS 1.2+ policy, HSTS                                               |
| 56    | DOM-based XSS                 | **N/A**       | No DOM (API-only)                                                   |
| 59    | Clickjacking                  | **Mitigated** | X-Frame-Options: DENY, CSP frame-ancestors                          |
| 61    | DDoS                          | **Mitigated** | Rate limiting, auto-blacklist, connection limits                    |
| 62    | Application Layer DoS         | **Mitigated** | Rate limiting, body size limits, timeouts                           |
| 63    | Resource Exhaustion           | **Mitigated** | Connection limits, body limits, query pagination                    |
| 64    | Slowloris                     | **Mitigated** | Read/Write/Idle timeouts                                            |
| 66    | SSRF                          | **Mitigated** | No outbound requests from user input                                |
| 67    | HTTP Parameter Pollution      | **Mitigated** | Fiber single-value extraction, strict validation                    |
| 68    | Insecure Redirects            | **N/A**       | No redirects in API                                                 |
| 71    | Clickjacking                  | **Mitigated** | X-Frame-Options: DENY                                               |
| 72    | Inadequate Session Timeout    | **Mitigated** | 15-min access token TTL, 24h refresh                                |
| 73    | Insufficient Logging          | **Mitigated** | Comprehensive audit trail (§12)                                     |
| 74    | Business Logic Flaws          | **Mitigated** | Refresh reuse detection, atomic token rotation                      |
| 75    | API Abuse                     | **Mitigated** | Rate limiting, IP binding, auto-blacklist                           |
| 85    | Insecure "Remember Me"        | **N/A**       | No "remember me" — token-based only                                 |
| 86    | CAPTCHA Bypass                | **N/A**       | Server-to-server API, no CAPTCHA needed                             |
| 87    | Blind SSRF                    | **Mitigated** | No user-controlled outbound requests                                |
| 89    | MIME Sniffing                 | **Mitigated** | X-Content-Type-Options: nosniff                                     |
| 91    | CSP Bypass                    | **Mitigated** | Strict CSP: default-src 'none'                                      |
| 93    | Race Conditions               | **Mitigated** | Atomic DB transactions for token rotation, SQLite serialized writes |
| 96    | Account Enumeration           | **Mitigated** | Constant-time comparison, uniform error responses, dummy bcrypt     |

---

## 15. Security Configuration Checklist

### Pre-Deployment

- [ ] `ENCRYPTION_KEY` set to 32 random bytes (hex-encoded, 64 chars)
- [ ] `JWT_SECRET` set to 64 random bytes (hex-encoded, 128 chars)
- [ ] `ADMIN_MASTER_KEY` set to 64 random bytes (hex-encoded)
- [ ] All three keys generated via: `openssl rand -hex 32` (or 64 for JWT/admin)
- [ ] `ENVIRONMENT` set to `prod`
- [ ] `LOG_LEVEL` set to `info`
- [ ] TLS termination configured at reverse proxy
- [ ] `TrustedProxies` configured with exact proxy IPs
- [ ] Default rate limits reviewed for expected traffic
- [ ] SQLite database file permissions set to `0600`
- [ ] Database directory permissions set to `0700`
- [ ] No debug endpoints exposed
- [ ] Server binary runs as non-root user

### Operational

- [ ] Monitor audit logs for CRITICAL events
- [ ] Review auto-blacklist hits weekly
- [ ] Rotate encryption keys quarterly
- [ ] Rotate JWT secret quarterly (with grace period for in-flight tokens)
- [ ] Review client registrations monthly
- [ ] Update Go dependencies monthly (`go get -u`)
- [ ] Backup database with encryption
- [ ] Test token revocation flow quarterly

### Key Generation Commands

```bash
# Master encryption key (32 bytes = 256 bits)
openssl rand -hex 32

# JWT signing secret (64 bytes = 512 bits)
openssl rand -hex 64

# Admin master key (64 bytes)
openssl rand -hex 64
```

---

## Appendix A: Security Response Codes

| Status | Meaning               | When Used                             |
| ------ | --------------------- | ------------------------------------- |
| 400    | Bad Request           | Invalid input, validation failure     |
| 401    | Unauthorized          | Missing/invalid/expired/revoked token |
| 403    | Forbidden             | IP blocked, client suspended          |
| 404    | Not Found             | Resource doesn't exist                |
| 413    | Payload Too Large     | Body exceeds limit                    |
| 429    | Too Many Requests     | Rate limit exceeded                   |
| 500    | Internal Server Error | Unexpected server failure             |

---

## Appendix B: Environment Variables

| Variable             | Required | Description                               | Example                    |
| -------------------- | -------- | ----------------------------------------- | -------------------------- |
| `ENCRYPTION_KEY`     | Yes      | AES-256 master key (hex)                  | `openssl rand -hex 32`     |
| `JWT_SECRET`         | Yes      | JWT HMAC signing key (hex)                | `openssl rand -hex 64`     |
| `ADMIN_MASTER_KEY`   | Yes      | Admin endpoint auth                       | `openssl rand -hex 64`     |
| `DB_PATH`            | No       | SQLite path (default: `./data/app.db`)    | `/var/lib/app_name/app.db` |
| `PORT`               | No       | Server port (default: 3000)               | `8080`                     |
| `ENVIRONMENT`        | No       | Runtime env (default: `dev`)              | `prod`                     |
| `LOG_LEVEL`          | No       | Log verbosity (default: `info`)           | `warn`                     |
| `IP_MODE`            | No       | IP filtering mode (default: `off`)        | `whitelist`                |
| `TRUSTED_PROXIES`    | No       | Comma-separated proxy IPs                 | `10.0.0.1,10.0.0.2`        |
| `GLOBAL_ALLOWED_IPS` | No       | Comma-separated CIDRs                     | `192.168.0.0/16`           |
| `TOKEN_BINDING_MODE` | No       | IP binding strictness (default: `strict`) | `subnet`                   |
| `BODY_LIMIT`         | No       | Max body bytes (default: 1048576)         | `2097152`                  |
