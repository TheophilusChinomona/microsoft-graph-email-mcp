"""
Microsoft Graph Email MCP Server -- OAuth2 Authentication (Hardened)

Security features:
  - PKCE (Proof Key for Code Exchange)
  - CSRF protection via state parameter
  - Encrypted token storage using Fernet (AES-128-CBC)
  - Auth code single-use enforcement
  - Auto token refresh with retry + backoff
  - Audit logging of auth events
"""

import hashlib
import json
import logging
import os
import base64
import secrets
import time
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlencode, urlparse, parse_qs

import httpx

from config import (
    CLIENT_ID, CLIENT_SECRET, REDIRECT_URI, SCOPES,
    AUTHORIZE_URL, DEVICE_CODE_URL, TOKEN_URL, TOKEN_CACHE_PATH,
    ENCRYPTION_KEY, RATE_LIMIT_RETRIES, RATE_LIMIT_BACKOFF_BASE
)

# Logging
log = logging.getLogger("graph-auth")
log.setLevel(logging.INFO)
if not log.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(logging.Formatter(
        "[%(asctime)s] %(levelname)s %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    ))
    log.addHandler(_handler)

# Audit log
_audit_log = logging.getLogger("graph-audit")
_audit_log.setLevel(logging.INFO)
_audit_path = Path(TOKEN_CACHE_PATH).parent / "audit.log"
_audit_path.parent.mkdir(parents=True, exist_ok=True)
if not _audit_log.handlers:
    _fh = logging.FileHandler(str(_audit_path))
    _fh.setFormatter(logging.Formatter("%(asctime)s | %(message)s"))
    _audit_log.addHandler(_fh)


def _audit(event: str, **kwargs):
    import getpass
    entry = f"event={event} user={getpass.getuser()}"
    for k, v in kwargs.items():
        entry += f" {k}={v}"
    _audit_log.info(entry)


# Encryption helpers

def _encrypt(data: str) -> bytes:
    if not ENCRYPTION_KEY:
        raise RuntimeError(
            "Encryption key required for token storage. "
            "Install 'cryptography' package: pip install cryptography"
        )
    try:
        from cryptography.fernet import Fernet
        f = Fernet(ENCRYPTION_KEY)
        return f.encrypt(data.encode())
    except Exception as e:
        log.error(f"Encryption failed: {e}")
        raise RuntimeError(f"Cannot encrypt tokens: {e}") from e


def _decrypt(data: bytes) -> str:
    if not ENCRYPTION_KEY:
        raise RuntimeError(
            "Encryption key required for token decryption. "
            "Tokens may have been encrypted with a different key."
        )
    try:
        from cryptography.fernet import Fernet
        f = Fernet(ENCRYPTION_KEY)
        return f.decrypt(data).decode()
    except Exception as e:
        log.error(f"Decryption failed: {e}")
        raise ValueError("Cannot decrypt tokens — key may have changed") from e


# PKCE helpers

def _generate_pkce() -> tuple[str, str]:
    code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
    digest = hashlib.sha256(code_verifier.encode()).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return code_verifier, code_challenge


# Token cache

def _load_tokens() -> dict | None:
    path = Path(TOKEN_CACHE_PATH)
    if not path.exists():
        return None
    try:
        encrypted_data = path.read_bytes()
        json_str = _decrypt(encrypted_data)
        tokens = json.loads(json_str)
        if not isinstance(tokens, dict):
            log.error("Token cache corrupted -- expected dict")
            return None
        return tokens
    except (json.JSONDecodeError, ValueError, OSError) as e:
        log.error(f"Failed to load tokens: {e}")
        return None


def _save_tokens(tokens: dict):
    path = Path(TOKEN_CACHE_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)

    json_str = json.dumps(tokens, separators=(",", ":"))
    encrypted = _encrypt(json_str)

    tmp_path = path.with_suffix(".tmp")
    tmp_path.write_bytes(encrypted)
    tmp_path.rename(path)

    try:
        os.chmod(path, 0o600)
    except OSError:
        pass

    log.info("Tokens saved to encrypted cache")


def _clear_tokens():
    path = Path(TOKEN_CACHE_PATH)
    if path.exists():
        try:
            size = path.stat().st_size
            path.write_bytes(secrets.token_bytes(size))
        except OSError:
            pass
        path.unlink()
        log.info("Tokens cleared from cache")
    _audit("logout")


# Token refresh with retry

def _refresh_access_token(refresh_token: str) -> dict:
    data = {
        "client_id": CLIENT_ID,
        "scope": " ".join(SCOPES),
        "refresh_token": refresh_token,
        "grant_type": "refresh_token",
    }
    if CLIENT_SECRET:
        data["client_secret"] = CLIENT_SECRET

    last_error = None
    for attempt in range(RATE_LIMIT_RETRIES + 1):
        try:
            with httpx.Client(timeout=30) as client:
                resp = client.post(TOKEN_URL, data=data)
                if resp.status_code == 429:
                    retry_after = int(resp.headers.get("Retry-After", RATE_LIMIT_BACKOFF_BASE ** attempt))
                    log.warning(f"Rate limited during token refresh, waiting {retry_after}s")
                    time.sleep(retry_after)
                    continue
                resp.raise_for_status()
                token_data = resp.json()
                _audit("token_refresh", status="success")
                return token_data
        except httpx.HTTPStatusError as e:
            last_error = e
            if e.response.status_code in (400, 401):
                _audit("token_refresh", status="failed", reason="invalid_grant")
                raise
            if attempt < RATE_LIMIT_RETRIES:
                time.sleep(RATE_LIMIT_BACKOFF_BASE ** attempt)
        except httpx.RequestError as e:
            last_error = e
            if attempt < RATE_LIMIT_RETRIES:
                time.sleep(RATE_LIMIT_BACKOFF_BASE ** attempt)

    _audit("token_refresh", status="failed", reason="max_retries")
    raise last_error or RuntimeError("Token refresh failed after retries")


# Local callback server (hardened)

class _CallbackHandler(BaseHTTPRequestHandler):
    auth_code: str | None = None
    auth_error: str | None = None
    expected_state: str | None = None
    code_used: bool = False

    def _send_security_headers(self):
        """Add security headers to all responses."""
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-XSS-Protection", "1; mode=block")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")

    def do_GET(self):
        parsed = urlparse(self.path)

        expected_path = urlparse(REDIRECT_URI).path
        if parsed.path != expected_path:
            self.send_response(404)
            self._send_security_headers()
            self.end_headers()
            self.wfile.write(b"Not found")
            return

        params = parse_qs(parsed.query)

        # Validate state (CSRF protection)
        state = params.get("state", [None])[0]
        if not state or state != self.expected_state:
            log.error("OAuth callback: state mismatch (possible CSRF)")
            _audit("oauth_callback", status="error", reason="state_mismatch")
            self.send_response(403)
            self._send_security_headers()
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"""
                <html><body style="font-family:system-ui;text-align:center;padding:60px">
                <h2>Security Error</h2>
                <p>State parameter mismatch -- possible CSRF attack. Authentication aborted.</p>
                </body></html>
            """)
            return

        if "code" in params:
            code = params["code"][0]
            # Prevent auth code replay
            if _CallbackHandler.code_used:
                log.warning("OAuth callback: auth code already used (possible replay)")
                _audit("oauth_callback", status="error", reason="code_replay")
                self.send_response(400)
                self._send_security_headers()
                self.end_headers()
                self.wfile.write(b"Authorization code already used")
                return

            _CallbackHandler.auth_code = code
            _CallbackHandler.code_used = True
            _audit("oauth_callback", status="success")
            self.send_response(200)
            self._send_security_headers()
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"""
                <html><body style="font-family:system-ui;text-align:center;padding:60px">
                <h2>Authentication successful!</h2>
                <p>You can close this tab and return to your terminal.</p>
                </body></html>
            """)
        elif "error" in params:
            error_desc = params.get("error_description", ["Unknown error"])[0]
            # Sanitize for log injection — strip control characters and newlines
            import re as _re
            error_desc = _re.sub(r"[\r\n\x00-\x1f\x7f]", "", error_desc)[:200]
            _CallbackHandler.auth_error = error_desc
            _audit("oauth_callback", status="error", reason=error_desc)
            self.send_response(400)
            self._send_security_headers()
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"""
                <html><body style="font-family:system-ui;text-align:center;padding:60px">
                <h2>Authentication failed</h2>
                <p>Details have been logged. Check your terminal.</p>
                </body></html>
            """)
        else:
            self.send_response(404)
            self._send_security_headers()
            self.end_headers()

    def log_message(self, format, *args):
        pass


def _run_callback_server(port: int, expected_state: str) -> str | None:
    _CallbackHandler.auth_code = None
    _CallbackHandler.auth_error = None
    _CallbackHandler.expected_state = expected_state
    _CallbackHandler.code_used = False

    try:
        server = HTTPServer(("localhost", port), _CallbackHandler)
        server.timeout = 120
        server.handle_request()
        server.server_close()
    except OSError as e:
        raise RuntimeError(f"Cannot bind to port {port}: {e}")

    if _CallbackHandler.auth_error:
        raise RuntimeError(f"OAuth error: {_CallbackHandler.auth_error}")
    return _CallbackHandler.auth_code


# Redirect URI validation

def _validate_redirect_uri(uri: str) -> None:
    parsed = urlparse(uri)
    if parsed.hostname not in ("localhost", "127.0.0.1"):
        raise ValueError(
            f"Redirect URI host must be localhost or 127.0.0.1, got: {parsed.hostname}"
        )
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Redirect URI scheme must be http or https, got: {parsed.scheme}")
    if parsed.fragment:
        raise ValueError("Redirect URI must not contain a fragment (#)")
    if parsed.username or parsed.password:
        raise ValueError("Redirect URI must not contain credentials")


def _validate_token_scopes(token_response: dict) -> list[str]:
    granted_scope_str = token_response.get("scope", "")
    granted_scopes = set(granted_scope_str.split())
    requested_scopes = set(SCOPES)

    missing = requested_scopes - granted_scopes
    if missing:
        log.warning(f"Missing scopes: {missing}")
        _audit("scope_warning", missing=",".join(missing))

    return list(granted_scopes)


# Device Code Flow (works on remote servers — no browser or localhost needed)

def _request_device_code() -> dict:
    """Request a device code from Microsoft identity platform."""
    data = {
        "client_id": CLIENT_ID,
        "scope": " ".join(SCOPES),
    }
    # Confidential client (has secret) includes it
    if CLIENT_SECRET:
        data["client_secret"] = CLIENT_SECRET

    with httpx.Client(timeout=30) as client:
        resp = client.post(DEVICE_CODE_URL, data=data)
        resp.raise_for_status()
        return resp.json()


def _poll_for_device_token(device_code: str, interval: int, expires_in: int) -> dict:
    """Poll the token endpoint until user completes device code auth."""
    data = {
        "client_id": CLIENT_ID,
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "device_code": device_code,
    }
    if CLIENT_SECRET:
        data["client_secret"] = CLIENT_SECRET

    deadline = time.time() + expires_in
    poll_interval = interval

    with httpx.Client(timeout=30) as client:
        while time.time() < deadline:
            try:
                resp = client.post(TOKEN_URL, data=data)
                body = resp.json()

                if resp.status_code == 200:
                    return body

                error = body.get("error", "")
                if error == "authorization_pending":
                    # User hasn't authenticated yet — keep polling
                    time.sleep(poll_interval)
                    continue
                elif error == "slow_down":
                    # Server asked us to slow down
                    poll_interval += 5
                    time.sleep(poll_interval)
                    continue
                elif error in ("expired_token", "access_denied"):
                    _audit("device_code_login", status="error", reason=error)
                    raise RuntimeError(f"Device code auth failed: {error}")
                else:
                    _audit("device_code_login", status="error", reason=error)
                    raise RuntimeError(f"Device code auth error: {error}")

            except httpx.HTTPStatusError as e:
                if e.response.status_code == 429:
                    retry_after = int(e.response.headers.get("Retry-After", 10))
                    time.sleep(retry_after)
                    continue
                raise
            except httpx.RequestError:
                time.sleep(poll_interval)
                continue

    _audit("device_code_login", status="error", reason="timeout")
    raise RuntimeError("Device code authentication timed out. Please try again.")


def login_device_code() -> dict:
    """
    Authenticate using OAuth 2.0 Device Code flow.

    Works on remote servers — no browser or localhost callback needed.
    The user opens https://microsoft.com/devicelogin on any device
    and enters the displayed code.
    """
    if not CLIENT_ID:
        raise ValueError(
            "MS_CLIENT_ID environment variable is required. "
            "Create an app registration at https://portal.azure.com"
        )

    log.info("Requesting device code...")
    device_info = _request_device_code()

    user_code = device_info["user_code"]
    verification_uri = device_info["verification_uri"]
    device_code = device_info["device_code"]
    interval = device_info.get("interval", 5)
    expires_in = device_info.get("expires_in", 900)

    # Print the code and URL for the user
    print(f"\n{'='*60}")
    print("Microsoft Graph Email -- Device Code Login")
    print(f"{'='*60}")
    print(f"\n  1. Open:  {verification_uri}")
    print(f"  2. Enter: {user_code}")
    print(f"\n  Waiting for authentication... (expires in {expires_in}s)\n")

    _audit("device_code_login", status="started", user_code=user_code)

    tokens = _poll_for_device_token(device_code, interval, expires_in)

    granted = _validate_token_scopes(tokens)
    tokens["_obtained_at"] = time.time()
    tokens["_granted_scopes"] = granted

    _save_tokens(tokens)
    _audit("login", status="success", method="device_code", scopes=",".join(granted))
    print("Authenticated! Tokens encrypted and cached.\n")

    return tokens


# Public API

def login(open_browser: bool = True) -> dict:
    if not CLIENT_ID:
        raise ValueError(
            "MS_CLIENT_ID environment variable is required. "
            "Create an app registration at https://portal.azure.com"
        )

    _validate_redirect_uri(REDIRECT_URI)

    code_verifier, code_challenge = _generate_pkce()
    state = secrets.token_urlsafe(32)

    parsed = urlparse(REDIRECT_URI)
    port = parsed.port or 8721

    auth_params = {
        "client_id": CLIENT_ID,
        "response_type": "code",
        "redirect_uri": REDIRECT_URI,
        "scope": " ".join(SCOPES),
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "response_mode": "query",
        "state": state,
    }
    auth_url = f"{AUTHORIZE_URL}?{urlencode(auth_params)}"

    print(f"\n{'='*60}")
    print("Microsoft Graph Email -- OAuth2 Login")
    print(f"{'='*60}")
    print(f"\nOpen this URL in your browser:\n")
    print(f"  {auth_url}\n")

    if open_browser:
        try:
            webbrowser.open(auth_url)
            print("(Browser should open automatically)")
        except Exception as e:
            log.debug(f"Could not open browser: {e}")

    print(f"Waiting for authentication on port {port}...")
    print("(You have 2 minutes to complete sign-in)\n")

    auth_code = _run_callback_server(port, expected_state=state)
    if not auth_code:
        _audit("login", status="error", reason="no_code")
        raise RuntimeError("No authorization code received")

    log.info("Authorization code received, exchanging for tokens...")

    data = {
        "client_id": CLIENT_ID,
        "scope": " ".join(SCOPES),
        "code": auth_code,
        "redirect_uri": REDIRECT_URI,
        "grant_type": "authorization_code",
        "code_verifier": code_verifier,
    }
    if CLIENT_SECRET:
        data["client_secret"] = CLIENT_SECRET

    try:
        with httpx.Client(timeout=30) as client:
            resp = client.post(TOKEN_URL, data=data)
            resp.raise_for_status()
            tokens = resp.json()
    except httpx.HTTPStatusError as e:
        _audit("login", status="error", reason=f"token_exchange_{e.response.status_code}")
        raise RuntimeError(f"Token exchange failed: {e.response.status_code}")

    granted = _validate_token_scopes(tokens)

    tokens["_obtained_at"] = time.time()
    tokens["_granted_scopes"] = granted

    _save_tokens(tokens)
    _audit("login", status="success", scopes=",".join(granted))
    print("Authenticated! Tokens encrypted and cached.\n")

    return tokens


def get_access_token() -> str:
    tokens = _load_tokens()
    if not tokens:
        raise ValueError(
            "Not authenticated. Run login() first, or use the 'graph_login' MCP tool."
        )

    access_token = tokens.get("access_token", "")
    expires_in = tokens.get("expires_in", 3600)
    obtained_at = tokens.get("_obtained_at", 0)

    if time.time() - obtained_at < expires_in - 300:
        return access_token

    refresh_token = tokens.get("refresh_token")
    if not refresh_token:
        _clear_tokens()
        raise ValueError(
            "No refresh token available. Run login() again to re-authenticate."
        )

    log.info("Access token expired, refreshing...")
    try:
        new_tokens = _refresh_access_token(refresh_token)
        new_tokens["_obtained_at"] = time.time()
        if "refresh_token" not in new_tokens:
            new_tokens["refresh_token"] = refresh_token
        if "_granted_scopes" in tokens:
            new_tokens["_granted_scopes"] = tokens["_granted_scopes"]
        _save_tokens(new_tokens)
        return new_tokens["access_token"]
    except Exception as e:
        _clear_tokens()
        _audit("token_refresh", status="error", reason=str(e)[:100])
        raise ValueError(f"Token refresh failed: {e}. Run login() again.")


def get_auth_headers() -> dict:
    return {
        "Authorization": f"Bearer {get_access_token()}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "Hermes-GraphEmail/1.0",
        "Cache-Control": "no-store",
        "Pragma": "no-cache",
    }


def logout():
    _clear_tokens()
    print("Logged out. Tokens securely cleared.")


def get_user_info() -> dict:
    from config import GRAPH_BASE_URL
    with httpx.Client(timeout=30) as client:
        resp = client.get(
            f"{GRAPH_BASE_URL}/me",
            headers=get_auth_headers()
        )
        resp.raise_for_status()
        return resp.json()


def get_granted_scopes() -> list[str]:
    tokens = _load_tokens()
    if not tokens:
        return []
    return tokens.get("_granted_scopes", [])
