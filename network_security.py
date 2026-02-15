"""
Network security module for Snapchat Memories Downloader.

Enforces URL allowlisting so the application can ONLY connect to known
Snapchat-controlled infrastructure domains.  Provides URL sanitization
helpers so that sensitive download URLs (which carry authentication tokens
in query parameters) are never written to log files in full.

Allowed domains
---------------
Only Snapchat's own CDN / infrastructure hostnames are permitted.
These are **not** developer-accessible endpoints (Snap Kit, Login Kit, etc.)
and cannot be intercepted or controlled by third-party Snap developers.

* ``*.snapchat.com``   – main Snapchat services (memories API, etc.)
* ``*.snap.com``       – Snap Inc. infrastructure
* ``*.sc-cdn.net``     – Snapchat's dedicated CDN for media delivery
"""

import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Domain allowlist
# ---------------------------------------------------------------------------

# Suffix-based matching (covers all subdomains)
ALLOWED_DOMAIN_SUFFIXES = (
    ".snapchat.com",
    ".snap.com",
    ".sc-cdn.net",
)

# Exact bare-domain matching (no subdomain)
ALLOWED_EXACT_DOMAINS = (
    "snapchat.com",
    "snap.com",
    "sc-cdn.net",
)

# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------


def is_allowed_url(url):
    """Return *True* if *url* points to a Snapchat-controlled domain.

    Only ``https`` (and ``http`` as a fallback) schemes are accepted.
    """
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        hostname = (parsed.hostname or "").lower()
        if not hostname:
            return False
        if hostname in ALLOWED_EXACT_DOMAINS:
            return True
        for suffix in ALLOWED_DOMAIN_SUFFIXES:
            if hostname.endswith(suffix):
                return True
        return False
    except Exception:
        return False


def validate_url(url):
    """Validate that *url* targets an allowed Snapchat domain.

    Raises :class:`ValueError` with a sanitised message if the URL is
    blocked.
    """
    if not is_allowed_url(url):
        safe = sanitize_url_for_logging(url)
        raise ValueError(
            f"URL blocked by security policy: {safe} — "
            "only Snapchat CDN domains are allowed"
        )


def sanitize_url_for_logging(url):
    """Return a redacted copy of *url* suitable for writing to log files.

    Only the scheme and hostname are kept; the path, query string and
    fragment (which may contain authentication tokens) are replaced with
    ``[REDACTED]``.
    """
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or "unknown"
        return f"{parsed.scheme}://{hostname}/[REDACTED]"
    except Exception:
        return "[INVALID URL]"


def sanitize_error_message(error):
    """Remove full URLs (with tokens) from an exception's string form.

    Replaces ``https://host/path?secret`` style substrings with
    ``https://host/[REDACTED]`` so that authentication tokens embedded in
    query strings are never written to log files.
    """
    import re
    text = str(error)
    # Match http(s) URLs and keep only the scheme + host portion
    def _redact(match):
        try:
            parsed = urlparse(match.group(0))
            return f"{parsed.scheme}://{parsed.hostname}/[REDACTED]"
        except Exception:
            return "[REDACTED URL]"
    return re.sub(r'https?://[^\s\'"<>]+', _redact, text)
