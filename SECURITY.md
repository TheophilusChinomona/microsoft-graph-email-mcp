# Security Policy

## Hardening Passes

This MCP server has undergone **three independent security hardening passes**:

| Pass | Method | Findings | Status |
|------|--------|----------|--------|
| **Pass 1** | Automated scan (Semgrep + Bandit) | 18 issues | ✅ Fixed |
| **Pass 2** | Deep manual review | 7 issues | ✅ Fixed |
| **Pass 3** | Red team penetration test (autonomous AI agent) | 12 issues | ✅ Fixed |

**Final audit result: 0 Critical, 0 High, 0 exploitable Medium.**

---

## Security Features

### Authentication & OAuth
- **PKCE** (Proof Key for Code Exchange) — prevents auth code interception
- **CSRF protection** via state parameter on OAuth callbacks
- **Auth code single-use enforcement** — prevents replay attacks
- **Encrypted token storage** using Fernet (AES-128-CBC) — **mandatory**, no fallback
- **Device Code flow** — works on remote servers, no browser/localhost needed
- **GRAPH_BASE_URL validated** against domain allowlist (Microsoft endpoints only)
- **OAuth error sanitization** — control chars stripped to prevent log injection
- **Security headers** on OAuth callback (X-Content-Type-Options, X-Frame-Options, CSP, etc.)

### Input Validation
- Email address format and length validation
- **Message ID regex tightened** — alphanumeric + specific punctuation only
- Folder name whitelist — **no disclosure of valid names on error**
- Subject line length and control character sanitization
- Email body size limits (1MB max) and **expanded XSS detection** (script tags, event handlers, javascript: URIs, data: URIs, vbscript:)
- Recipient list limits (500 max)
- Attachment size limits (10MB default, configurable)

### Data Protection
- Tokens encrypted at rest with Fernet (AES)
- Encryption key stored with 0600 permissions — **separated from token cache path**
- **Encryption is mandatory** — no fallback to unencrypted storage
- Secure token clearing (overwrite before delete)
- Error sanitization — no internal details leak to users

### Attachment Security
- Size limits (10MB default, configurable)
- **60+ dangerous file types blocked** via expanded blocklist (.exe, .dll, .bat, .cmd, .ps1, .vbs, .js, .py, .rb, .sh, .jar, .class, .html, .svg, .hta, .scr, .pif, .com, .msi, .apk, and more)
- **Configurable attachment directory** — not hardcoded (env: `GRAPH_ATTACHMENT_DIR`)
- Path traversal protection — strict validation after `resolve()`
- Override via `GRAPH_ALLOW_DANGEROUS_ATTACHMENTS=true` (not recommended)

### Search Security
- Query sanitization — control characters stripped, quotes AND backslashes escaped
- Query length limits (1000 chars)
- Folder whitelist enforcement — **no valid folder name disclosure**

### Send Security
- **Per-minute rate limiting** (default: 20/min, configurable via `GRAPH_MAX_SENDS_PER_MINUTE`)
- **Per-hour rate limiting** (default: 100/hour, configurable via `GRAPH_MAX_SENDS_PER_HOUR`)
- **XSS detection** in email body — warns on script tags, event handlers, javascript: URIs, data: URIs

### Audit Logging
- All email operations logged with timestamps
- Authentication events logged (login, logout, token refresh)
- Rate limit events logged
- Audit log stored in `.auth/audit.log` (gitignored)

### Network Security
- Rate limiting with exponential backoff on all API calls
- Automatic retry on transient failures (5xx errors)
- Token auto-refresh on 401 responses
- Request timeouts (30s default, 60s for attachments)

---

## Red Team Findings (Pass 3)

Conducted by an autonomous red team agent with fresh context (no knowledge of implementation). All 12 findings fixed:

| # | Severity | Finding | Fix |
|---|----------|---------|-----|
| C1 | Critical | Dangerous attachment blocklist incomplete — .py, .html, .svg, .jar, .apk, .hta, .vbs and 50+ others not blocked | Expanded to 60+ types |
| H1 | High | GRAPH_BASE_URL not validated — SSRF possible if attacker sets base URL | Domain allowlist enforced |
| H2 | High | OAuth error description not sanitized — log injection via crafted state | Control chars stripped |
| M1 | Medium | Attachment save path hardcoded to /pentest/ directory | Configurable via GRAPH_ATTACHMENT_DIR |
| M2 | Medium | XSS detection missed onerror=, javascript:, data: URIs | Expanded detection patterns |
| M3 | Medium | Search query sanitization missed backslash escaping | Backslash escaping added |
| M4 | Medium | No send rate limiting — flood/spam possible | Per-min and per-hour limits added |
| M5 | Medium | Encryption key stored in same directory as tokens | Key path separated |
| M6 | Medium | Message ID regex too permissive | Tightened to alphanumeric + specific chars |
| L1 | Low | Folder validation error reveals valid folder names | Generic error message |

---

## Reporting a Vulnerability

If you discover a security vulnerability, please:

1. **Do NOT** open a public issue
2. Email: theophilus@acextic.com
3. Include: description, reproduction steps, impact assessment
4. Response time: within 48 hours

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest  | ✅        |

## Dependencies

Minimal dependency surface:
- `fastmcp` — MCP server framework
- `httpx` — HTTP client
- `cryptography` — Token encryption (required)

All dependencies pinned to minimum versions with known security patches.

## Configuration Security

Required environment variables:
- `MS_CLIENT_ID` — Azure AD app registration client ID
- `MS_CLIENT_SECRET` — Azure AD client secret (for confidential apps)

Optional:
- `GRAPH_TOKEN_KEY` — Custom encryption key (generated if not set)
- `GRAPH_MAX_ATTACHMENT_SIZE` — Attachment download limit (default: 10MB)
- `GRAPH_ATTACHMENT_DIR` — Directory for saved attachments (default: ./attachments)
- `GRAPH_ALLOW_DANGEROUS_ATTACHMENTS` — Set to `true` to bypass blocklist (not recommended)
- `GRAPH_MAX_SENDS_PER_MINUTE` — Send rate limit (default: 20)
- `GRAPH_MAX_SENDS_PER_HOUR` — Send rate limit (default: 100)
- `GRAPH_BASE_URL` — Override Graph API base URL (validated against Microsoft domains)

**Never commit `.env` files, `.auth/` directory, `*.key`, or `*.pem` files to version control.**
