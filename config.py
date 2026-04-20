"""
Microsoft Graph Email MCP Server -- Configuration
"""

import os
import sys
from pathlib import Path

# Azure AD / Entra ID
TENANT_ID = os.environ.get("MS_TENANT_ID", "common")
CLIENT_ID = os.environ.get("MS_CLIENT_ID", "")
CLIENT_SECRET = os.environ.get("MS_CLIENT_SECRET", "")
REDIRECT_URI = os.environ.get("MS_REDIRECT_URI", "http://localhost:8721/callback")

# Scopes
SCOPES = os.environ.get(
    "MS_SCOPES",
    "Mail.Read Mail.Send Mail.ReadWrite User.Read offline_access"
).split()

# Graph API
GRAPH_BASE_URL = os.environ.get("GRAPH_BASE_URL", "https://graph.microsoft.com/v1.0")

# Validate base URL to prevent SSRF / token exfiltration
_ALLOWED_GRAPH_BASES = {
    "https://graph.microsoft.com/v1.0",
    "https://graph.microsoft.com/beta",
    "https://graph.microsoft.us/v1.0",  # GCC High
    "https://dod-graph.microsoft.us/v1.0",  # DoD
}
if GRAPH_BASE_URL not in _ALLOWED_GRAPH_BASES:
    print(
        f"[SECURITY ERROR] GRAPH_BASE_URL must be one of: {_ALLOWED_GRAPH_BASES}. "
        f"Got: {GRAPH_BASE_URL}",
        file=sys.stderr
    )
    raise SystemExit(1)

# Token cache
_default_cache = str(Path(__file__).parent / ".auth" / "tokens.json")
TOKEN_CACHE_PATH = os.environ.get("GRAPH_TOKEN_CACHE_PATH", _default_cache)

# Security settings
MAX_ATTACHMENT_SIZE = int(os.environ.get("GRAPH_MAX_ATTACHMENT_SIZE", 10 * 1024 * 1024))  # 10MB
RATE_LIMIT_RETRIES = int(os.environ.get("GRAPH_RATE_LIMIT_RETRIES", 3))
RATE_LIMIT_BACKOFF_BASE = 2

# Send rate limiting
MAX_SENDS_PER_MINUTE = int(os.environ.get("GRAPH_MAX_SENDS_PER_MINUTE", 20))
MAX_SENDS_PER_HOUR = int(os.environ.get("GRAPH_MAX_SENDS_PER_HOUR", 100))

# Attachment settings
ATTACHMENT_DIR = os.environ.get("GRAPH_ATTACHMENT_DIR", str(Path(__file__).parent / "attachments"))
ALLOW_DANGEROUS_ATTACHMENTS = os.environ.get("GRAPH_ALLOW_DANGEROUS_ATTACHMENTS", "").lower() == "true"

# OAuth2 endpoints
AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
AUTHORIZE_URL = f"{AUTHORITY}/oauth2/v2.0/authorize"
DEVICE_CODE_URL = f"{AUTHORITY}/oauth2/v2.0/devicecode"
TOKEN_URL = f"{AUTHORITY}/oauth2/v2.0/token"

# Encryption key for token cache
# Store key SEPARATELY from tokens to prevent single-point compromise
_KEY_PATH = str(Path.home() / ".config" / "graph-email" / ".token_key")

def _get_encryption_key() -> bytes:
    env_key = os.environ.get("GRAPH_TOKEN_KEY")
    if env_key:
        return env_key.encode()

    key_path = Path(_KEY_PATH)
    if key_path.exists():
        return key_path.read_bytes().strip()

    try:
        from cryptography.fernet import Fernet
        key = Fernet.generate_key()
        key_path.parent.mkdir(parents=True, exist_ok=True)
        key_path.write_bytes(key)
        try:
            os.chmod(key_path, 0o600)
        except OSError:
            pass
        print(f"[SECURITY] Generated new encryption key: {key_path}", file=sys.stderr)
        return key
    except ImportError:
        print(
            "[SECURITY ERROR] 'cryptography' package is required. "
            "Install it: pip install cryptography",
            file=sys.stderr
        )
        raise SystemExit(1)

ENCRYPTION_KEY = _get_encryption_key()
