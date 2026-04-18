# Microsoft Graph Email MCP Server (Security-Hardened)

Send and receive emails via Microsoft 365 / Outlook using Microsoft Graph API, integrated with Hermes as MCP tools.

## Features

- Read, send, reply, search emails
- Manage folders, attachments, drafts
- 16 MCP tools for full email management
- Security-hardened OAuth2 with PKCE + CSRF protection
- Encrypted token storage, audit logging, rate limiting

## Quick Start

```bash
cd ~/microsoft-graph-email-mcp
pip install -r requirements.txt

# Set environment variables (see .env.example)
export MS_TENANT_ID="your-tenant-id"
export MS_CLIENT_ID="your-client-id"
export MS_CLIENT_SECRET="your-client-secret"

# Test
python3 test_server.py
```

## Azure Setup

1. Azure Portal -> App registrations -> New registration
2. Redirect URI: `http://localhost:8721/callback` (Web)
3. API permissions (Delegated): Mail.Read, Mail.ReadWrite, Mail.Send, User.Read, offline_access
4. Grant admin consent
5. Copy Client ID + Client Secret

See SKILL.md for full tool documentation.

## Files

- `server.py` -- FastMCP server with all tools
- `auth.py` -- OAuth2 authentication (PKCE, encrypted storage)
- `config.py` -- Configuration
- `SKILL.md` -- Agent-facing skill docs
- `test_server.py` -- Security audit + smoke tests
- `.env.example` -- Environment variable template

## License

MIT
