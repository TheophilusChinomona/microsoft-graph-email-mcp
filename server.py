#!/usr/bin/env python3
"""
Microsoft Graph Email MCP Server for Hermes (Security-Hardened)

Security features:
  - Input validation on all parameters
  - Rate limiting with exponential backoff
  - Error sanitization
  - Audit logging of all email operations
  - Attachment size limits
  - HTML injection detection
"""

import json
import logging
import re
import sys
import time
from pathlib import Path

from fastmcp import FastMCP
import httpx

sys.path.insert(0, str(Path(__file__).parent))
from config import (
    GRAPH_BASE_URL, MAX_ATTACHMENT_SIZE, RATE_LIMIT_RETRIES,
    RATE_LIMIT_BACKOFF_BASE
)
from auth import (
    login, login_device_code, logout, get_access_token, get_auth_headers,
    get_user_info, get_granted_scopes
)

log = logging.getLogger("graph-email")
log.setLevel(logging.INFO)
if not log.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(logging.Formatter(
        "[%(asctime)s] %(levelname)s %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    ))
    log.addHandler(_handler)

# Audit logger — shared with auth.py via same logger name
_audit = logging.getLogger("graph-audit")
_audit.setLevel(logging.INFO)
_audit_path = Path(__file__).parent / ".auth" / "audit.log"
_audit_path.parent.mkdir(parents=True, exist_ok=True)
if not _audit.handlers:
    _fh = logging.FileHandler(str(_audit_path))
    _fh.setFormatter(logging.Formatter("%(asctime)s | %(message)s"))
    _audit.addHandler(_fh)

# Dangerous file extensions for attachment download
# Blocklist approach — comprehensive list of executable/script types
DANGEROUS_EXTENSIONS = {
    # Windows executables
    ".exe", ".bat", ".cmd", ".com", ".msi", ".scr", ".pif", ".inf", ".reg",
    # Windows scripts
    ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta",
    ".msh", ".msh1", ".msh2", ".mshxml",
    # PowerShell
    ".ps1", ".psm1", ".psd1", ".ps1xml", ".pssc",
    # Unix scripts
    ".sh", ".bash", ".csh", ".ksh", ".zsh",
    # Programming languages
    ".py", ".pyw", ".pyc", ".pyo",
    ".pl", ".pm", ".rb", ".php", ".php3", ".php4", ".php5", ".phtml",
    ".java", ".class", ".jar",
    ".go", ".rs", ".c", ".cpp", ".h",
    # Shared libraries
    ".dll", ".sys", ".drv", ".ocx",
    ".elf", ".so", ".dylib", ".o", ".a",
    # Markup with executable potential
    ".svg", ".html", ".htm", ".xhtml", ".xht", ".shtml",
    # Mobile
    ".apk", ".ipa", ".xap",
    # Shortcuts/links
    ".lnk", ".scf", ".url",
    # Macro-enabled documents
    ".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".potm",
    # Other dangerous
    ".iso", ".img", ".vhd", ".vhdx",
}

# Override via env var (for specialized deployments)
if os.environ.get("GRAPH_ALLOW_DANGEROUS_ATTACHMENTS", "").lower() == "true":
    DANGEROUS_EXTENSIONS = set()

# Send rate limiting
import collections
_send_timestamps: list[float] = []
MAX_SENDS_PER_MINUTE = int(os.environ.get("GRAPH_MAX_SENDS_PER_MINUTE", "20"))
MAX_SENDS_PER_HOUR = int(os.environ.get("GRAPH_MAX_SENDS_PER_HOUR", "100"))


def _check_send_rate():
    """Rate limit send_email to prevent abuse."""
    import time
    now = time.time()

    # Clean old timestamps
    _send_timestamps[:] = [t for t in _send_timestamps if now - t < 3600]

    # Check per-minute limit
    recent_minute = [t for t in _send_timestamps if now - t < 60]
    if len(recent_minute) >= MAX_SENDS_PER_MINUTE:
        raise ValueError(
            f"Send rate limit exceeded. Max {MAX_SENDS_PER_MINUTE} emails per minute."
        )

    # Check per-hour limit
    if len(_send_timestamps) >= MAX_SENDS_PER_HOUR:
        raise ValueError(
            f"Hourly send limit exceeded. Max {MAX_SENDS_PER_HOUR} emails per hour."
        )

    _send_timestamps.append(now)

# Request ID counter for audit trail
import itertools
_request_counter = itertools.count(1)


def _next_request_id() -> str:
    return f"req-{next(_request_counter):06d}"


mcp = FastMCP("Microsoft Graph Email")


# Validation helpers

VALID_FOLDERS = {
    "inbox", "sentitems", "drafts", "deleteditems", "junkemail",
    "archive", "outbox", "clutter", "conversationhistory",
    "recoverableitemsdeletions"
}

EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")
MESSAGE_ID_REGEX = re.compile(r"^[A-Za-z0-9+/=]{10,200}$")
SCRIPT_PATTERN = re.compile(r"<script[^>]*>.*?</script>", re.IGNORECASE | re.DOTALL)
# Broader XSS pattern — catches onerror, onload, on*, javascript:, data:
XSS_PATTERN = re.compile(
    r"<script|</script|javascript:|data:text/html|on\w+\s*=",
    re.IGNORECASE
)

# Attachment save directory — configurable, defaults to user's home
import os
ATTACHMENT_DIR = Path(os.environ.get(
    "GRAPH_ATTACHMENT_DIR",
    str(Path.home() / ".graph-email" / "attachments")
)).resolve()


def _validate_email(email: str) -> str:
    if not email or not isinstance(email, str):
        raise ValueError("Email address cannot be empty")
    email = email.strip().lower()
    if not EMAIL_REGEX.match(email):
        raise ValueError(f"Invalid email address format: {email}")
    if len(email) > 320:
        raise ValueError("Email address too long (max 320 chars)")
    return email


def _validate_email_list(emails: list[str]) -> list[str]:
    if not emails:
        raise ValueError("Recipient list cannot be empty")
    if len(emails) > 500:
        raise ValueError("Too many recipients (max 500)")
    return [_validate_email(e) for e in emails]


def _validate_message_id(message_id: str) -> str:
    if not message_id or not isinstance(message_id, str):
        raise ValueError("Message ID cannot be empty")
    message_id = message_id.strip()
    if not MESSAGE_ID_REGEX.match(message_id):
        raise ValueError("Invalid message ID format")
    return message_id


def _validate_folder(folder: str) -> str:
    if not folder or not isinstance(folder, str):
        raise ValueError("Folder name cannot be empty")
    folder = folder.strip().lower().replace(" ", "")
    if folder not in VALID_FOLDERS:
        raise ValueError("Invalid folder name")
    return folder


def _validate_subject(subject: str) -> str:
    if not subject or not isinstance(subject, str):
        raise ValueError("Subject cannot be empty")
    subject = subject.strip()
    if len(subject) > 255:
        raise ValueError("Subject too long (max 255 chars)")
    subject = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", subject)
    return subject


def _validate_body(body: str) -> str:
    if not body or not isinstance(body, str):
        raise ValueError("Body cannot be empty")
    if len(body) > 1_000_000:
        raise ValueError("Email body too large (max 1MB)")
    if XSS_PATTERN.search(body):
        log.warning("Email body contains potentially dangerous HTML patterns")
    return body


def _validate_body_type(body_type: str) -> str:
    """Validate and normalize body type."""
    if not body_type or not isinstance(body_type, str):
        return "HTML"
    normalized = body_type.strip().upper()
    if normalized not in ("HTML", "TEXT"):
        return "HTML"
    return normalized


def _sanitize_search_query(query: str) -> str:
    """Sanitize search query to prevent injection."""
    # Remove null bytes and control characters
    query = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", query)
    # Strip leading/trailing whitespace
    query = query.strip()
    # Escape quotes and backslashes that could break the $search parameter
    query = query.replace("\\", "\\\\").replace('"', '\\"')
    # Truncate to reasonable length
    return query[:1000]


def _sanitize_error(error: Exception, operation: str) -> str:
    if isinstance(error, httpx.HTTPStatusError):
        status = error.response.status_code
        if status == 401:
            return "Authentication expired. Please run graph_login again."
        elif status == 403:
            return f"Permission denied for {operation}. Check that your Azure app has the required API permissions."
        elif status == 404:
            return f"Resource not found for {operation}. Check the ID and try again."
        elif status == 429:
            retry_after = error.response.headers.get("Retry-After", "unknown")
            return f"Rate limited by Microsoft Graph. Try again in {retry_after} seconds."
        elif status >= 500:
            return f"Microsoft Graph service error ({status}). Try again later."
        else:
            return f"Request failed for {operation} (HTTP {status})."
    elif isinstance(error, ValueError):
        return str(error)
    elif isinstance(error, httpx.TimeoutException):
        return f"Request timed out for {operation}. Try again."
    elif isinstance(error, httpx.RequestError):
        return f"Network error during {operation}. Check your internet connection."
    else:
        log.exception(f"Unexpected error in {operation}")
        return f"An unexpected error occurred during {operation}. Check logs for details."


# Graph API request helper with retry

def _graph_request(
    method: str,
    path: str,
    operation: str,
    json_data: dict | None = None,
    params: dict | None = None,
    timeout: int = 30
) -> dict | None:
    headers = get_auth_headers()
    url = f"{GRAPH_BASE_URL}{path}"
    last_error = None

    for attempt in range(RATE_LIMIT_RETRIES + 1):
        try:
            with httpx.Client(timeout=timeout) as client:
                resp = client.request(method, url, headers=headers, json=json_data, params=params)

                if resp.status_code == 429:
                    retry_after = int(resp.headers.get("Retry-After", RATE_LIMIT_BACKOFF_BASE ** attempt))
                    log.warning(f"Rate limited on {operation}, waiting {retry_after}s (attempt {attempt+1})")
                    _audit("rate_limit", operation=operation, wait=retry_after)
                    time.sleep(retry_after)
                    continue

                if resp.status_code == 401 and attempt == 0:
                    log.info(f"Token expired during {operation}, refreshing...")
                    headers = get_auth_headers()
                    continue

                if resp.status_code >= 500 and attempt < RATE_LIMIT_RETRIES:
                    wait = RATE_LIMIT_BACKOFF_BASE ** attempt
                    log.warning(f"Server error {resp.status_code} on {operation}, retrying in {wait}s")
                    time.sleep(wait)
                    continue

                resp.raise_for_status()

                if resp.status_code == 204:
                    _audit("api_call", operation=operation, status="success", code=204)
                    return None

                result = resp.json()
                _audit("api_call", operation=operation, status="success", code=resp.status_code)
                return result

        except httpx.HTTPStatusError as e:
            last_error = e
            if e.response.status_code in (400, 403, 404):
                _audit("api_call", operation=operation, status="error", code=e.response.status_code)
                raise
        except httpx.RequestError as e:
            last_error = e
            if attempt < RATE_LIMIT_RETRIES:
                wait = RATE_LIMIT_BACKOFF_BASE ** attempt
                log.warning(f"Network error on {operation}, retrying in {wait}s: {e}")
                time.sleep(wait)

    _audit("api_call", operation=operation, status="error", reason="max_retries")
    raise last_error or RuntimeError(f"Request failed after {RATE_LIMIT_RETRIES} retries")


# Auth tools

@mcp.tool()
def graph_login() -> str:
    """Authenticate with Microsoft Graph using Device Code flow.
    Works on any server — local or remote. No browser or localhost needed.
    You'll get a code to enter at https://microsoft.com/devicelogin from any device.
    Run this first before using any email tools. Tokens are encrypted, cached, and auto-refreshed."""
    try:
        tokens = login_device_code()
        user = get_user_info()
        return json.dumps({
            "status": "success",
            "user": user.get("displayName", "Unknown"),
            "email": user.get("mail") or user.get("userPrincipalName", "Unknown"),
            "message": "Authentication successful! Tokens encrypted and cached."
        }, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e)})


@mcp.tool()
def graph_login_browser() -> str:
    """Authenticate with Microsoft Graph using browser OAuth flow (localhost only).
    Use this if you're running the server locally with a browser available.
    For remote servers, use graph_login (device code) instead."""
    try:
        tokens = login(open_browser=True)
        user = get_user_info()
        return json.dumps({
            "status": "success",
            "user": user.get("displayName", "Unknown"),
            "email": user.get("mail") or user.get("userPrincipalName", "Unknown"),
            "message": "Authentication successful! Tokens encrypted and cached."
        }, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e)})


@mcp.tool()
def graph_logout() -> str:
    """Clear cached Microsoft Graph authentication tokens (secure overwrite)."""
    logout()
    return json.dumps({"status": "success", "message": "Logged out. Tokens securely cleared."})


@mcp.tool()
def graph_whoami() -> str:
    """Show the currently authenticated Microsoft user's profile."""
    try:
        user = get_user_info()
        return json.dumps({
            "displayName": user.get("displayName"),
            "email": user.get("mail") or user.get("userPrincipalName"),
            "jobTitle": user.get("jobTitle"),
            "officeLocation": user.get("officeLocation"),
            "id": user.get("id"),
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": _sanitize_error(e, "whoami")})


@mcp.tool()
def graph_auth_status() -> str:
    """Check authentication status and granted OAuth scopes."""
    try:
        scopes = get_granted_scopes()
        if not scopes:
            return json.dumps({"authenticated": False, "message": "Not logged in. Run graph_login first."})

        from config import SCOPES
        requested = set(SCOPES)
        granted = set(scopes)
        missing = requested - granted

        return json.dumps({
            "authenticated": True,
            "granted_scopes": sorted(granted),
            "requested_scopes": sorted(requested),
            "missing_scopes": sorted(missing) if missing else None,
            "all_granted": len(missing) == 0,
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": _sanitize_error(e, "auth_status")})


# Email reading tools

@mcp.tool()
def list_messages(
    folder: str = "inbox",
    top: int = 10,
    skip: int = 0,
    order_by: str = "receivedDateTime",
    order_dir: str = "desc"
) -> str:
    """List emails from a mail folder.

    Args:
        folder: Mail folder -- inbox, sentitems, drafts, deleteditems, junkemail, archive, outbox
        top: Number of emails to return (max 50)
        skip: Number of emails to skip (for pagination)
        order_by: Sort field -- receivedDateTime, subject, importance
        order_dir: Sort direction -- desc (newest first) or asc (oldest first)
    """
    try:
        folder = _validate_folder(folder)
        top = max(1, min(top, 50))
        skip = max(0, skip)
        if order_by not in ("receivedDateTime", "subject", "importance"):
            order_by = "receivedDateTime"
        if order_dir not in ("asc", "desc"):
            order_dir = "desc"

        params = {
            "$top": top,
            "$skip": skip,
            "$orderby": f"{order_by} {order_dir}",
            "$select": "id,subject,from,toRecipients,receivedDateTime,isRead,importance,hasAttachments,bodyPreview",
        }

        data = _graph_request(
            "GET", f"/me/mailFolders/{folder}/messages",
            operation=f"list_messages({folder})", params=params
        )

        messages = []
        for msg in data.get("value", []):
            sender = msg.get("from", {}).get("emailAddress", {})
            to_list = [r.get("emailAddress", {}).get("address", "") for r in msg.get("toRecipients", [])]
            messages.append({
                "id": msg["id"],
                "subject": msg.get("subject", "(no subject)"),
                "from": sender.get("address", "Unknown"),
                "from_name": sender.get("name", ""),
                "to": to_list,
                "received": msg.get("receivedDateTime", ""),
                "isRead": msg.get("isRead", False),
                "importance": msg.get("importance", "normal"),
                "hasAttachments": msg.get("hasAttachments", False),
                "preview": msg.get("bodyPreview", "")[:200],
            })

        return json.dumps({
            "folder": folder, "count": len(messages),
            "has_more": len(messages) == top, "messages": messages
        }, indent=2)

    except Exception as e:
        return json.dumps({"error": _sanitize_error(e, "list_messages")})


@mcp.tool()
def get_message(message_id: str, include_body: bool = True) -> str:
    """Get the full content of an email by its ID.

    Args:
        message_id: The message ID (from list_messages or search_messages)
        include_body: Whether to include the full email body (HTML)
    """
    try:
        message_id = _validate_message_id(message_id)
        select_fields = "id,subject,from,toRecipients,ccRecipients,bccRecipients,receivedDateTime,sentDateTime,isRead,importance,hasAttachments,body,internetMessageHeaders"
        if not include_body:
            select_fields = select_fields.replace(",body", ",bodyPreview")

        data = _graph_request(
            "GET", f"/me/messages/{message_id}",
            operation="get_message", params={"$select": select_fields}
        )

        sender = data.get("from", {}).get("emailAddress", {})
        to_list = [r.get("emailAddress", {}) for r in data.get("toRecipients", [])]
        cc_list = [r.get("emailAddress", {}) for r in data.get("ccRecipients", [])]

        result = {
            "id": data["id"],
            "subject": data.get("subject", "(no subject)"),
            "from": {"address": sender.get("address"), "name": sender.get("name")},
            "to": to_list, "cc": cc_list,
            "received": data.get("receivedDateTime"),
            "sent": data.get("sentDateTime"),
            "isRead": data.get("isRead"),
            "importance": data.get("importance"),
            "hasAttachments": data.get("hasAttachments"),
        }

        if include_body and "body" in data:
            result["body"] = data["body"]
            result["body_content_type"] = data["body"].get("contentType", "html")
        elif "bodyPreview" in data:
            result["preview"] = data["bodyPreview"]

        return json.dumps(result, indent=2)

    except Exception as e:
        return json.dumps({"error": _sanitize_error(e, "get_message")})


@mcp.tool()
def search_messages(query: str, folder: str | None = None, top: int = 10) -> str:
    """Search emails using Microsoft Graph search.

    Args:
        query: Search query. Supports:
               - "from:john@example.com" -- by sender
               - "subject:meeting" -- in subject
               - "hasAttachments:true" -- with attachments
               - "isRead:false" -- unread only
               - "received>=2024-01-01" -- date range
        folder: Optional folder to search (default: all folders)
        top: Max results (max 50)
    """
    try:
        if not query or not isinstance(query, str):
            raise ValueError("Search query cannot be empty")
        query = _sanitize_search_query(query)
        top = max(1, min(top, 50))
        if folder:
            folder = _validate_folder(folder)

        params = {
            "$search": f'"{query}"',
            "$top": top,
            "$select": "id,subject,from,toRecipients,receivedDateTime,isRead,importance,hasAttachments,bodyPreview",
        }

        url = f"/me/mailFolders/{folder}/messages" if folder else "/me/messages"
        data = _graph_request("GET", url, operation="search_messages", params=params)

        messages = []
        for msg in data.get("value", []):
            sender = msg.get("from", {}).get("emailAddress", {})
            messages.append({
                "id": msg["id"],
                "subject": msg.get("subject", "(no subject)"),
                "from": sender.get("address", "Unknown"),
                "from_name": sender.get("name", ""),
                "received": msg.get("receivedDateTime", ""),
                "isRead": msg.get("isRead", False),
                "preview": msg.get("bodyPreview", "")[:200],
            })

        return json.dumps({
            "query": query, "folder": folder or "all",
            "count": len(messages), "messages": messages
        }, indent=2)

    except Exception as e:
        return json.dumps({"error": _sanitize_error(e, "search_messages")})


# Email sending tools

@mcp.tool()
def send_email(
    to: list[str], subject: str, body: str, body_type: str = "HTML",
    cc: list[str] | None = None, bcc: list[str] | None = None,
    importance: str = "normal"
) -> str:
    """Send an email via Microsoft Graph.

    Args:
        to: List of recipient email addresses (max 500)
        subject: Email subject line (max 255 chars)
        body: Email body content (max 1MB)
        body_type: "HTML" or "Text"
        cc: Optional CC recipients
        bcc: Optional BCC recipients
        importance: "low", "normal", or "high"
    """
    try:
        to = _validate_email_list(to)
        subject = _validate_subject(subject)
        body = _validate_body(body)
        body_type = _validate_body_type(body_type)
        if importance not in ("low", "normal", "high"):
            importance = "normal"
        if cc:
            cc = _validate_email_list(cc)
        if bcc:
            bcc = _validate_email_list(bcc)

        req_id = _next_request_id()
        _check_send_rate()
        _audit("send_email_start", req_id=req_id, to_count=len(to), subject=subject[:50])

        def _make_recipients(addresses):
            return [{"emailAddress": {"address": addr}} for addr in addresses]

        email_message = {
            "message": {
                "subject": subject,
                "body": {"contentType": body_type, "content": body},
                "toRecipients": _make_recipients(to),
                "importance": importance,
            }
        }
        if cc:
            email_message["message"]["ccRecipients"] = _make_recipients(cc)
        if bcc:
            email_message["message"]["bccRecipients"] = _make_recipients(bcc)

        _graph_request("POST", "/me/sendMail", operation="send_email", json_data=email_message)

        return json.dumps({"status": "sent", "to": to, "subject": subject, "message": "Email sent successfully!"})

    except Exception as e:
        return json.dumps({"error": _sanitize_error(e, "send_email")})


@mcp.tool()
def reply_to_email(
    message_id: str, body: str, body_type: str = "HTML",
    reply_all: bool = False, add_cc: list[str] | None = None
) -> str:
    """Reply to an email.

    Args:
        message_id: ID of the message to reply to
        body: Reply body content
        body_type: "HTML" or "Text"
        reply_all: If True, reply to all recipients
        add_cc: Optional additional CC recipients
    """
    try:
        message_id = _validate_message_id(message_id)
        body = _validate_body(body)
        body_type = _validate_body_type(body_type)
        if add_cc:
            add_cc = _validate_email_list(add_cc)

        reply_data = {"message": {"body": {"contentType": body_type, "content": body}}}
        if add_cc:
            reply_data["message"]["ccRecipients"] = [
                {"emailAddress": {"address": addr}} for addr in add_cc
            ]

        endpoint = "replyAll" if reply_all else "reply"
        _graph_request("POST", f"/me/messages/{message_id}/{endpoint}", operation=f"reply", json_data=reply_data)

        return json.dumps({"status": "replied", "message_id": message_id, "reply_all": reply_all, "message": "Reply sent!"})

    except Exception as e:
        return json.dumps({"error": _sanitize_error(e, "reply_to_email")})


@mcp.tool()
def create_draft(
    to: list[str], subject: str, body: str, body_type: str = "HTML",
    cc: list[str] | None = None
) -> str:
    """Create a draft email (saved in Drafts folder, not sent).

    Args:
        to: List of recipient email addresses
        subject: Email subject (max 255 chars)
        body: Email body (max 1MB)
        body_type: "HTML" or "Text"
        cc: Optional CC recipients
    """
    try:
        to = _validate_email_list(to)
        subject = _validate_subject(subject)
        body = _validate_body(body)
        body_type = _validate_body_type(body_type)
        if cc:
            cc = _validate_email_list(cc)

        draft = {
            "subject": subject,
            "body": {"contentType": body_type, "content": body},
            "toRecipients": [{"emailAddress": {"address": addr}} for addr in to],
        }
        if cc:
            draft["ccRecipients"] = [{"emailAddress": {"address": addr}} for addr in cc]

        data = _graph_request("POST", "/me/messages", operation="create_draft", json_data=draft)

        return json.dumps({"status": "draft_created", "id": data["id"], "subject": data.get("subject"), "created": data.get("createdDateTime")})

    except Exception as e:
        return json.dumps({"error": _sanitize_error(e, "create_draft")})


# Folder and organization tools

@mcp.tool()
def list_mail_folders(top: int = 50) -> str:
    """List all mail folders in the mailbox."""
    try:
        top = max(1, min(top, 100))
        data = _graph_request(
            "GET", "/me/mailFolders", operation="list_mail_folders",
            params={"$top": top, "$select": "id,displayName,parentFolderId,totalItemCount,unreadItemCount"}
        )

        folders = []
        for f in data.get("value", []):
            folders.append({
                "id": f["id"], "name": f["displayName"],
                "total_items": f.get("totalItemCount", 0),
                "unread_items": f.get("unreadItemCount", 0),
            })

        return json.dumps({"folders": folders}, indent=2)

    except Exception as e:
        return json.dumps({"error": _sanitize_error(e, "list_mail_folders")})


@mcp.tool()
def move_message(message_id: str, destination_folder: str) -> str:
    """Move an email to a different folder.

    Args:
        message_id: ID of the message to move
        destination_folder: Target folder -- inbox, sentitems, drafts, deleteditems, archive, junkemail
    """
    try:
        message_id = _validate_message_id(message_id)
        destination_folder = _validate_folder(destination_folder)

        data = _graph_request(
            "POST", f"/me/messages/{message_id}/move",
            operation="move_message", json_data={"destinationId": destination_folder}
        )

        return json.dumps({"status": "moved", "message_id": message_id, "destination": destination_folder, "new_id": data.get("id") if data else None})

    except Exception as e:
        return json.dumps({"error": _sanitize_error(e, "move_message")})


@mcp.tool()
def mark_as_read(message_id: str, is_read: bool = True) -> str:
    """Mark an email as read or unread.

    Args:
        message_id: ID of the message
        is_read: True to mark as read, False to mark as unread
    """
    try:
        message_id = _validate_message_id(message_id)
        _graph_request("PATCH", f"/me/messages/{message_id}", operation="mark_as_read", json_data={"isRead": bool(is_read)})
        return json.dumps({"status": "updated", "message_id": message_id, "is_read": bool(is_read)})

    except Exception as e:
        return json.dumps({"error": _sanitize_error(e, "mark_as_read")})


@mcp.tool()
def delete_message(message_id: str, permanent: bool = False) -> str:
    """Delete an email.

    Args:
        message_id: ID of the message to delete
        permanent: If True, permanently delete. If False, move to Deleted Items.
    """
    try:
        message_id = _validate_message_id(message_id)

        if permanent:
            _graph_request("DELETE", f"/me/messages/{message_id}", operation="delete_message(permanent)")
            action = "permanently deleted"
        else:
            _graph_request("POST", f"/me/messages/{message_id}/move", operation="delete_message(soft)", json_data={"destinationId": "deleteditems"})
            action = "moved to Deleted Items"

        _audit("delete_message", message_id=message_id[:20], permanent=permanent)
        return json.dumps({"status": "deleted", "message_id": message_id, "action": action})

    except Exception as e:
        return json.dumps({"error": _sanitize_error(e, "delete_message")})


# Attachment tools

@mcp.tool()
def list_attachments(message_id: str) -> str:
    """List attachments on an email.

    Args:
        message_id: ID of the message
    """
    try:
        message_id = _validate_message_id(message_id)

        data = _graph_request(
            "GET", f"/me/messages/{message_id}/attachments",
            operation="list_attachments",
            params={"$select": "id,name,contentType,size,isInline,lastModifiedDateTime"}
        )

        attachments = []
        for att in data.get("value", []):
            attachments.append({
                "id": att["id"], "name": att.get("name", "unnamed"),
                "content_type": att.get("contentType", ""),
                "size_bytes": att.get("size", 0),
                "is_inline": att.get("isInline", False),
            })

        return json.dumps({"message_id": message_id, "count": len(attachments), "attachments": attachments}, indent=2)

    except Exception as e:
        return json.dumps({"error": _sanitize_error(e, "list_attachments")})


@mcp.tool()
def get_attachment(message_id: str, attachment_id: str, save_path: str | None = None) -> str:
    """Download an attachment from an email.

    Args:
        message_id: ID of the message
        attachment_id: ID of the attachment
        save_path: Optional file path to save the attachment to
    """
    try:
        message_id = _validate_message_id(message_id)
        if not attachment_id or not isinstance(attachment_id, str):
            raise ValueError("Attachment ID cannot be empty")

        data = _graph_request(
            "GET", f"/me/messages/{message_id}/attachments/{attachment_id}",
            operation="get_attachment", timeout=60
        )

        result = {
            "name": data.get("name", "unnamed"),
            "content_type": data.get("contentType", ""),
            "size_bytes": data.get("size", 0),
            "is_inline": data.get("isInline", False),
        }

        size = data.get("size", 0)
        if size > MAX_ATTACHMENT_SIZE:
            result["warning"] = f"Attachment is {size} bytes, exceeds limit of {MAX_ATTACHMENT_SIZE} bytes"
            result["message"] = "Attachment too large to download."
            return json.dumps(result, indent=2)

        # Block dangerous file extensions
        att_name = data.get("name", "")
        att_ext = Path(att_name).suffix.lower()
        if att_ext in DANGEROUS_EXTENSIONS:
            result["warning"] = f"Blocked download of dangerous file type: {att_ext}"
            result["message"] = "This attachment type is blocked for security. Set GRAPH_ALLOW_DANGEROUS=true to override."
            _audit("attachment_blocked", name=att_name, extension=att_ext)
            return json.dumps(result, indent=2)

        if "contentBytes" in data and save_path:
            import base64
            content = base64.b64decode(data["contentBytes"])
            save_path_obj = Path(save_path).resolve()

            # Strict path traversal protection — validate after resolve
            ALLOWED_BASE = ATTACHMENT_DIR.resolve()
            try:
                save_path_obj.relative_to(ALLOWED_BASE)
            except ValueError:
                raise ValueError(
                    f"save_path must be within {ALLOWED_BASE}. "
                    f"Got: {save_path_obj}"
                )

            save_path_obj.parent.mkdir(parents=True, exist_ok=True)
            save_path_obj.write_bytes(content)
            result["saved_to"] = str(save_path_obj)
            result["message"] = f"Attachment saved to {save_path_obj}"
            _audit("attachment_download", name=data.get("name"), size=size)
        elif "contentBytes" in data:
            result["message"] = "Attachment available. Provide save_path to save to disk."
        elif "contentLocation" in data:
            result["content_url"] = data["contentLocation"]

        return json.dumps(result, indent=2)

    except Exception as e:
        return json.dumps({"error": _sanitize_error(e, "get_attachment")})


if __name__ == "__main__":
    mcp.run()
