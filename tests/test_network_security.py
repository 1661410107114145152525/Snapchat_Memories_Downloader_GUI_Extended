"""
Tests for the network_security module – URL allowlisting and log sanitization.
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
import network_security


# ---------------------------------------------------------------------------
# is_allowed_url
# ---------------------------------------------------------------------------

class TestIsAllowedUrl:
    """URL allowlist should accept only Snapchat-controlled domains."""

    @pytest.mark.parametrize("url", [
        "https://app.snapchat.com/dmd/memories?id=abc123",
        "https://memories.snapchat.com/download?token=xyz",
        "https://bolt-gcdn.sc-cdn.net/some/path?sig=token",
        "https://cf-st.sc-cdn.net/media/file.jpg",
        "https://api.snap.com/resource",
        "https://snapchat.com/path",
        "https://sc-cdn.net/path",
        "http://snapchat.com/fallback",
    ])
    def test_allowed_urls(self, url):
        assert network_security.is_allowed_url(url) is True

    @pytest.mark.parametrize("url", [
        "https://evil.com/steal?data=secret",
        "https://notsnapchat.com/fake",
        "https://example.com/snapchat.com",
        "https://snapchat.com.evil.com/path",
        "https://fakesc-cdn.net/path",
        "ftp://snapchat.com/file",
        "file:///etc/passwd",
        "",
        "not-a-url",
        "https://",
        "https://developer.snapchat.com.attacker.org/exfil",
        "https://s3.amazonaws.com/bucket/file",
        "https://storage.googleapis.com/bucket/file",
    ])
    def test_blocked_urls(self, url):
        assert network_security.is_allowed_url(url) is False


# ---------------------------------------------------------------------------
# validate_url
# ---------------------------------------------------------------------------

class TestValidateUrl:
    def test_valid_url_no_exception(self):
        # Should not raise
        network_security.validate_url("https://app.snapchat.com/dmd/memories?id=abc")

    def test_blocked_url_raises(self):
        with pytest.raises(ValueError, match="URL blocked by security policy"):
            network_security.validate_url("https://evil.com/exfiltrate")

    def test_error_message_does_not_leak_path(self):
        """The ValueError message must NOT contain the full path/query."""
        try:
            network_security.validate_url("https://evil.com/secret/path?token=abc123")
        except ValueError as exc:
            msg = str(exc)
            assert "secret" not in msg
            assert "token" not in msg
            assert "abc123" not in msg


# ---------------------------------------------------------------------------
# sanitize_url_for_logging
# ---------------------------------------------------------------------------

class TestSanitizeUrlForLogging:
    def test_redacts_path_and_query(self):
        result = network_security.sanitize_url_for_logging(
            "https://app.snapchat.com/dmd/memories?id=secret_token_123"
        )
        assert "secret_token_123" not in result
        assert "/dmd/memories" not in result
        assert "app.snapchat.com" in result
        assert "[REDACTED]" in result

    def test_handles_empty_string(self):
        result = network_security.sanitize_url_for_logging("")
        assert "INVALID" in result or "unknown" in result.lower()

    def test_handles_none(self):
        # Should not crash
        result = network_security.sanitize_url_for_logging(None)
        assert isinstance(result, str)


# ---------------------------------------------------------------------------
# sanitize_error_message
# ---------------------------------------------------------------------------

class TestSanitizeErrorMessage:
    def test_strips_url_from_http_error(self):
        msg = "404 Client Error: Not Found for url: https://app.snapchat.com/dmd/memories?token=SECRET"
        result = network_security.sanitize_error_message(msg)
        assert "SECRET" not in result
        assert "token" not in result
        assert "app.snapchat.com" in result
        assert "[REDACTED]" in result

    def test_preserves_non_url_text(self):
        msg = "Connection timed out after 60 seconds"
        result = network_security.sanitize_error_message(msg)
        assert result == msg

    def test_handles_multiple_urls(self):
        msg = "Redirect from https://a.snapchat.com/x?t=1 to https://b.sc-cdn.net/y?s=2"
        result = network_security.sanitize_error_message(msg)
        assert "t=1" not in result
        assert "s=2" not in result


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
