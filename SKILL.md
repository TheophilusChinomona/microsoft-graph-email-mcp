---
name: microsoft-graph-email
description: Send and receive emails via Microsoft Graph API through Hermes MCP tools
category: email
tags: [email, microsoft, graph-api, outlook, mcp]
---

# Microsoft Graph Email -- Agent Skill

Send, read, search, and manage emails via Microsoft 365 / Outlook using Microsoft Graph API.

## Setup (One-Time)

1. Run `graph_login` -- opens Microsoft sign-in page in browser
2. Sign in with your Microsoft 365 account
3. Tokens are encrypted and cached locally

**Check auth:** Run `graph_auth_status` to see who is logged in and what scopes are granted.

## Security Features

- Encrypted token storage (Fernet/AES-128-CBC)
- CSRF protection via OAuth2 state parameter
- PKCE for auth code interception prevention
- Input validation on all parameters
- Rate limiting with exponential backoff
- Error sanitization (no raw API errors leaked)
- Audit logging to `.auth/audit.log`
- Attachment size limits (default 10MB)

## Tools Reference

### Authentication
| Tool | Purpose |
|------|---------|
| `graph_login` | Sign in via browser (one-time setup) |
| `graph_logout` | Securely clear cached tokens |
| `graph_whoami` | Show current user info |
| `graph_auth_status` | Check auth status and granted scopes |

### Reading Emails
| Tool | Purpose |
|------|---------|
| `list_messages` | List emails from a folder |
| `get_message` | Read full email content by ID |
| `search_messages` | Search emails with queries |
| `list_mail_folders` | List all mail folders |

### Sending Emails
| Tool | Purpose |
|------|---------|
| `send_email` | Send a new email |
| `reply_to_email` | Reply to an email |
| `create_draft` | Create a draft (not sent) |

### Organization
| Tool | Purpose |
|------|---------|
| `move_message` | Move email to different folder |
| `mark_as_read` | Mark as read/unread |
| `delete_message` | Delete email (soft or permanent) |

### Attachments
| Tool | Purpose |
|------|---------|
| `list_attachments` | List attachments on a message |
| `get_attachment` | Download an attachment |

## Common Workflows

### Read recent emails
```
1. list_messages(folder="inbox", top=10)
2. get_message(message_id="<id from step 1>")
```

### Search and reply
```
1. search_messages(query="from:boss@company.com isRead:false", top=5)
2. get_message(message_id="<id>")
3. reply_to_email(message_id="<id>", body="<your reply>")
```

### Send an email
```
send_email(
  to=["recipient@example.com"],
  subject="Meeting Tomorrow",
  body="<p>Hi, let's meet at 2pm.</p>",
  body_type="HTML"
)
```

## Search Query Syntax

- `from:email@domain.com` -- filter by sender
- `subject:keyword` -- search subject line
- `isRead:false` -- unread only
- `hasAttachments:true` -- has attachments
- `received>=2024-01-01` -- date filter

## Folder Names

- `inbox`, `sentitems`, `drafts`, `deleteditems`, `junkemail`, `archive`, `outbox`

## Error Handling

- **"Not authenticated"** -> Run `graph_login` first
- **"Authentication expired"** -> Re-run `graph_login`
- **"Permission denied"** -> Check Azure app permissions
- **"Rate limited"** -> Wait for retry-after period

## Pitfalls

- First-time setup requires Azure app registration (MS_CLIENT_ID, MS_CLIENT_SECRET)
- Body type matters -- set `body_type="HTML"` when sending HTML
- Message IDs are long strings like `AAMkAGI2TG93AAA=`, don't truncate
- Folder names are case-insensitive, use lowercase
- Tokens auto-refresh but refresh tokens expire (~90 days)
- Audit log at `.auth/audit.log` for compliance
