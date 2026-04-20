# Microsoft Graph Email MCP Server (Security-Hardened)

Send and receive emails via Microsoft 365 / Outlook using Microsoft Graph API, integrated with Hermes as MCP tools.

**Triple-hardened security**: 3 independent security passes (automated scan, deep manual review, red team pentest) — 0 Critical, 0 High, 0 exploitable Medium findings.

## Features

- Read, send, reply, search, draft emails
- Manage folders and attachments
- 16 MCP tools for full email management
- Security-hardened OAuth2 with PKCE + CSRF protection
- Encrypted token storage (mandatory Fernet/AES)
- 60+ dangerous attachment types blocked
- Per-minute/hour send rate limiting
- XSS detection in email bodies
- Audit logging for all operations
- Domain-validated Graph API base URL

## Quick Start

```bash
cd ~/microsoft-graph-email-mcp
pip install -r requirements.txt

# Required
export MS_TENANT_ID="your-tenant-id"
export MS_CLIENT_ID="your-client-id"
export MS_CLIENT_SECRET="your-client-secret"

# Optional (sensible defaults)
export GRAPH_ATTACHMENT_DIR="./attachments"    # Where to save attachments
export GRAPH_MAX_SENDS_PER_MINUTE="20"         # Send rate limit
export GRAPH_MAX_SENDS_PER_HOUR="100"          # Hourly send limit
export GRAPH_MAX_ATTACHMENT_SIZE="10485760"    # 10MB default

# Start the MCP server
python3 server.py
```

### Login (Device Code — works everywhere)

When you call `graph_login`, the server displays:

```
============================================================
Microsoft Graph Email -- Device Code Login
============================================================

  1. Open:  https://microsoft.com/devicelogin
  2. Enter: ABCD-1234

  Waiting for authentication... (expires in 900s)
```

Open the URL on **any device** (phone, laptop, tablet), enter the code, and you're in. No browser, localhost, or SSH tunnel needed on the server.

For local development with a browser, use `graph_login_browser` instead.

## Azure Setup

1. Azure Portal → App registrations → New registration
2. Redirect URI: `http://localhost:8721/callback` (Web)
3. API permissions (Delegated): Mail.Read, Mail.ReadWrite, Mail.Send, User.Read, offline_access
4. Grant admin consent
5. Copy Client ID + Client Secret

## MCP Tools (16)

| Category | Tools |
|----------|-------|
| **Auth** | `graph_login` (device code), `graph_login_browser`, `graph_logout`, `graph_whoami`, `graph_auth_status` |
| **Read** | `read_emails`, `search_emails`, `get_email_content` |
| **Send** | `send_email`, `reply_email`, `forward_email` |
| **Manage** | `list_folders`, `move_email`, `delete_email`, `mark_as_read` |
| **Drafts** | `create_draft`, `update_draft`, `send_draft`, `list_drafts` |
| **Attachments** | `download_attachment`, `list_attachments` |

See [SKILL.md](SKILL.md) for full tool documentation.

## Security

This server has been hardened through three security passes:

1. **Automated scan** — Semgrep (SAST) + Bandit (Python security)
2. **Deep manual review** — OWASP Top 10, input validation, error handling
3. **Red team pentest** — Autonomous AI agent attempted exploitation from fresh context

**Result: 37 findings identified, all fixed.** See [SECURITY.md](SECURITY.md) for full details.

## Files

- `server.py` — FastMCP server with all 16 tools
- `auth.py` — OAuth2 authentication (PKCE, encrypted storage, security headers)
- `config.py` — Configuration with validation
- `SKILL.md` — Agent-facing skill docs
- `SECURITY.md` — Security policy and hardening audit trail
- `test_server.py` — Security audit + smoke tests

## License

MIT
