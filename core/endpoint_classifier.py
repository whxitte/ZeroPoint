"""
ZeroPoint :: core/endpoint_classifier.py
==========================================
Classifies raw crawled URLs into interesting vs noise.

Interesting endpoints feed directly into:
  - Immediate Discord/Telegram alerts
  - Module 3 (Scanner) as additional targets

Design: rules are data, not code. Edit INTEREST_RULES to tune sensitivity.
"""

from __future__ import annotations

import math
import re
import string
from typing import List, Set, Tuple
from urllib.parse import urlparse

from loguru import logger


# ─────────────────────────────────────────────────────────────────────────────
# Interest rules — (regex_pattern, tag, description)
# Applied against the full URL path (lowercased)
# ─────────────────────────────────────────────────────────────────────────────

INTEREST_RULES: List[Tuple[str, str, str]] = [
    # ── Authentication & Access ──────────────────────────────────────────
    (r"/login",               "login",    "Login endpoint"),
    (r"/signin",              "login",    "Sign-in endpoint"),
    (r"/auth",                "auth",     "Authentication endpoint"),
    (r"/oauth",               "oauth",    "OAuth endpoint"),
    (r"/sso",                 "sso",      "SSO endpoint"),
    (r"/saml",                "saml",     "SAML endpoint"),
    (r"/logout",              "auth",     "Logout endpoint"),
    (r"/register",            "register", "Registration endpoint"),
    (r"/signup",              "register", "Sign-up endpoint"),
    (r"/reset.?password",     "auth",     "Password reset"),
    (r"/forgot.?password",    "auth",     "Password forgot"),
    (r"/2fa",                 "auth",     "Two-factor auth"),
    (r"/mfa",                 "auth",     "MFA endpoint"),
    (r"/verify",              "auth",     "Verification endpoint"),
    (r"/token",               "token",    "Token endpoint"),
    (r"/jwt",                 "token",    "JWT endpoint"),
    (r"/api.?key",            "apikey",   "API key endpoint"),

    # ── API & Data Endpoints ─────────────────────────────────────────────
    (r"/api/",                "api",      "API endpoint"),
    (r"/v[0-9]+/",            "api",      "Versioned API endpoint"),
    (r"/graphql",             "graphql",  "GraphQL endpoint"),
    (r"/rest/",               "api",      "REST API endpoint"),
    (r"/rpc",                 "api",      "RPC endpoint"),
    (r"/webhook",             "webhook",  "Webhook endpoint"),
    (r"/callback",            "callback", "Callback endpoint"),
    (r"/export",              "export",   "Data export endpoint"),
    (r"/download",            "download", "Download endpoint"),
    (r"/import",              "import",   "Data import endpoint"),

    # ── File Upload & Management ─────────────────────────────────────────
    (r"/upload",              "upload",   "File upload endpoint"),
    (r"/file",                "upload",   "File endpoint"),
    (r"/attachment",          "upload",   "Attachment endpoint"),
    (r"/media",               "upload",   "Media endpoint"),

    # ── Admin & Internal ─────────────────────────────────────────────────
    (r"/admin",               "admin",    "Admin panel"),
    (r"/dashboard",           "admin",    "Dashboard"),
    (r"/management",          "admin",    "Management panel"),
    (r"/internal",            "internal", "Internal endpoint"),
    (r"/staff",               "admin",    "Staff panel"),
    (r"/superuser",           "admin",    "Superuser endpoint"),
    (r"/console",             "admin",    "Console"),
    (r"/debug",               "debug",    "Debug endpoint"),
    (r"/test",                "debug",    "Test endpoint"),
    (r"/staging",             "debug",    "Staging endpoint"),
    (r"/dev/",                "debug",    "Dev endpoint"),

    # ── Configuration & Secrets ──────────────────────────────────────────
    (r"/config",              "config",   "Config endpoint"),
    (r"/settings",            "config",   "Settings endpoint"),
    (r"/env",                 "config",   "Env endpoint"),
    (r"/\.env",               "secret",   ".env file exposure"),
    (r"/\.git",               "secret",   ".git directory exposure"),
    (r"/backup",              "backup",   "Backup endpoint"),
    (r"\.bak$",               "backup",   "Backup file"),
    (r"\.sql$",               "backup",   "SQL dump"),
    (r"\.zip$",               "backup",   "Archive file"),
    (r"\.tar",                "backup",   "Archive file"),

    # ── Payment & Sensitive Business Logic ──────────────────────────────
    (r"/payment",             "payment",  "Payment endpoint"),
    (r"/checkout",            "payment",  "Checkout endpoint"),
    (r"/billing",             "payment",  "Billing endpoint"),
    (r"/subscription",        "payment",  "Subscription endpoint"),
    (r"/invoice",             "payment",  "Invoice endpoint"),
    (r"/refund",              "payment",  "Refund endpoint"),

    # ── SSRF & Proxy Targets ─────────────────────────────────────────────
    (r"[?&](url|uri|path|file|src|dest|redirect|return|next)=",  "ssrf", "SSRF parameter"),
    (r"[?&](proxy|host|domain|feed|site|data)=",                  "ssrf", "SSRF parameter"),

    # ── Open Redirect ────────────────────────────────────────────────────
    (r"[?&](redirect|return_url|next|forward|redir|to|goto)=",    "redirect", "Open redirect parameter"),

    # ── SQLi / XSS prone parameters ──────────────────────────────────────
    (r"[?&](id|user_id|uid|account|order_id|product_id)=",        "idor",  "IDOR parameter"),
    (r"[?&](q|search|query|keyword|term|s)=",                     "xss",   "Search/reflect parameter"),
    (r"[?&](page|p|limit|offset|size|from|sort)=",                "sqli",  "Pagination parameter"),
]

# Extensions that are noise — skip entirely
NOISE_EXTENSIONS: Set[str] = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".woff", ".woff2", ".ttf", ".eot",
    ".css", ".map",
    ".mp4", ".mp3", ".avi", ".mov",
    ".pdf",  # PDFs can be interesting but flag separately
}

# JS file pattern — route to SecretFinder
JS_PATTERN = re.compile(r"\.js(\?.*)?$", re.IGNORECASE)


def is_noise_url(url: str) -> bool:
    """Return True if this URL is definitely not worth analysing."""
    try:
        parsed = urlparse(url.lower())
        path   = parsed.path
        # Skip static asset extensions
        for ext in NOISE_EXTENSIONS:
            if path.endswith(ext):
                return True
        # Skip tracking/analytics garbage
        noise_patterns = [
            "google-analytics", "googletagmanager", "hotjar",
            "facebook.com", "twitter.com", "linkedin.com",
            "cdn.jsdelivr", "cdnjs.cloudflare", "unpkg.com",
        ]
        full = url.lower()
        if any(p in full for p in noise_patterns):
            return True
        return False
    except Exception:
        return True


def classify_endpoint(url: str) -> Tuple[bool, List[str]]:
    """
    Classify a URL as interesting or noise.

    Returns:
        (is_interesting: bool, tags: List[str])

    is_interesting=True means this endpoint deserves manual attention
    and should trigger an alert if it's new.
    """
    if is_noise_url(url):
        return False, []

    url_lower = url.lower()
    tags: List[str] = []

    for pattern, tag, _ in INTEREST_RULES:
        if re.search(pattern, url_lower):
            if tag not in tags:
                tags.append(tag)

    return bool(tags), tags


def is_js_file(url: str) -> bool:
    """Return True if the URL points to a JavaScript file."""
    return bool(JS_PATTERN.search(url))


# ─────────────────────────────────────────────────────────────────────────────
# Shannon entropy — used to filter low-entropy "secrets" (false positives)
# ─────────────────────────────────────────────────────────────────────────────

def shannon_entropy(value: str) -> float:
    """
    Calculate Shannon entropy of a string.
    High entropy (>3.5) = likely a real random secret.
    Low entropy (<3.0)  = likely a placeholder like 'YOUR_API_KEY_HERE'.
    """
    if not value:
        return 0.0
    counts = {c: value.count(c) for c in set(value)}
    length = len(value)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
        if count > 0
    )


# Module-level singleton
endpoint_classifier = type("EndpointClassifier", (), {
    "classify":      staticmethod(classify_endpoint),
    "is_js_file":    staticmethod(is_js_file),
    "is_noise":      staticmethod(is_noise_url),
    "entropy":       staticmethod(shannon_entropy),
})()