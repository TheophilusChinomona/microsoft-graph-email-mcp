#!/usr/bin/env python3
"""Smoke test for Microsoft Graph Email MCP Server."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))


def test_config():
    from config import CLIENT_ID, TENANT_ID, GRAPH_BASE_URL, ENCRYPTION_KEY
    from config import MAX_ATTACHMENT_SIZE, RATE_LIMIT_RETRIES
    print(f"Tenant: {TENANT_ID}")
    print(f"Graph URL: {GRAPH_BASE_URL}")
    print(f"Max attachment: {MAX_ATTACHMENT_SIZE / 1024 / 1024:.0f}MB")
    print(f"Encryption: {'ENABLED' if ENCRYPTION_KEY else 'DISABLED'}")
    return True


def test_encryption():
    from auth import _encrypt, _decrypt
    test_data = '{"access_token": "test123", "refresh_token": "refresh456"}'
    encrypted = _encrypt(test_data)
    decrypted = _decrypt(encrypted)
    assert decrypted == test_data
    assert encrypted != test_data.encode()
    print(f"Encrypt/decrypt: OK ({len(encrypted)} bytes)")
    return True


def test_pkce():
    from auth import _generate_pkce
    v1, c1 = _generate_pkce()
    v2, c2 = _generate_pkce()
    assert v1 != v2
    assert c1 != c2
    assert len(v1) == 43
    print(f"PKCE: OK (verifiers unique, 43 chars each)")
    return True


def test_validation():
    from server import _validate_email, _validate_message_id, _validate_folder, _validate_subject

    for email in ("user@example.com", "test+tag@co.uk"):
        assert _validate_email(email) == email.lower()

    for bad in ("", "not-email", "@missing.com"):
        try:
            _validate_email(bad)
            assert False
        except ValueError:
            pass

    _validate_message_id("AAMkAGI2TG93AAA=")
    try:
        _validate_message_id("")
        assert False
    except ValueError:
        pass

    for f in ("inbox", "sentitems", "INBOX"):
        _validate_folder(f)
    try:
        _validate_folder("not_real")
        assert False
    except ValueError:
        pass

    _validate_subject("Hello")
    try:
        _validate_subject("")
        assert False
    except ValueError:
        pass

    print("Validation: OK")
    return True


def test_error_sanitization():
    from server import _sanitize_error
    import httpx

    class MockResponse:
        def __init__(self, status, headers=None):
            self.status_code = status
            self._headers = headers or {}
        @property
        def headers(self):
            return self._headers

    err = _sanitize_error(httpx.HTTPStatusError("401", request=None, response=MockResponse(401)), "test")
    assert "login" in err.lower()

    err = _sanitize_error(httpx.HTTPStatusError("403", request=None, response=MockResponse(403)), "test")
    assert "permission" in err.lower() or "denied" in err.lower()

    err = _sanitize_error(ValueError("test"), "test")
    assert "test" in err

    print("Error sanitization: OK")
    return True


def test_server_loads():
    from server import mcp
    assert mcp is not None
    assert mcp.name == "Microsoft Graph Email"
    print(f"Server: {mcp.name} loads OK")
    return True


def test_audit_log():
    from auth import _audit
    _audit("test_event", action="smoke_test")
    audit_path = Path(__file__).parent / ".auth" / "audit.log"
    assert audit_path.exists()
    assert "test_event" in audit_path.read_text()
    print(f"Audit log: OK")
    return True


def main():
    print("=" * 50)
    print("Microsoft Graph Email MCP -- Security Audit")
    print("=" * 50)
    print()

    tests = [
        ("Config", test_config),
        ("Encryption", test_encryption),
        ("PKCE", test_pkce),
        ("Validation", test_validation),
        ("Error Sanitization", test_error_sanitization),
        ("Server Load", test_server_loads),
        ("Audit Log", test_audit_log),
    ]

    passed = 0
    failed = 0
    for name, fn in tests:
        try:
            fn()
            passed += 1
        except Exception as e:
            print(f"  FAILED: {name}: {e}")
            failed += 1

    print()
    print(f"Results: {passed} passed, {failed} failed")
    if failed == 0:
        print("All tests passed!")
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
