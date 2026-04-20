# Security Policy

## Security Features

This MCP server implements security hardening at every layer:

### Authentication
- **PKCE** (Proof Key for Code Exchange) — prevents auth code interception
- **CSRF protection** via state parameter on OAuth callbacks
- **Auth code single-use enforcement** — prevents replay attacks
- **Encrypted token storage** using Fernet (AES-128-CBC)
- **Automatic token refresh** with retry and backoff

### Input Validation
- Email address format and length validation
- Message ID format validation
- Folder name whitelist
- Subject line length and control character sanitization
- Email body size limits (1MB max) and script tag detection
- Recipient list limits (500 max)
- Attachment size limits (10MB default, configurable)

### Data Protection
- Tokens encrypted at rest with Fernet (AES)
- Encryption key stored with 0600 permissions
- **Encryption is mandatory** — no fallback to unencrypted storage
- Secure token clearing (overwrite before delete)
- Error sanitization — no internal details leak to users

### Attachment Security
- Size limits (10MB default, configurable)
- **Dangerous file type blocking** — .exe, .bat, .sh, .dll, .ps1, etc. are blocked by default
- Path traversal protection — saves restricted to `/pentest/results`
- Strict path validation after `resolve()`

### Search Security
- Query sanitization — control characters stripped, quotes escaped
- Query length limits (1000 chars)
- Folder whitelist enforcement

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
- `GRAPH_TOKEN_KEY` — Custom encryption key for token cache
- `GRAPH_MAX_ATTACHMENT_SIZE` — Attachment download limit

**Never commit `.env` files or `.auth/` directory to version control.**
