"""Secret-detection patterns for jshunter.

Each pattern is a dict with:
  name: human-readable rule name
  regex: compiled pattern (must contain one capture group for the secret value)
  severity: CRITICAL | HIGH | MEDIUM | LOW
  description: what a finding means

Patterns are ordered; first match wins per value to avoid double-reporting.
Entropy-gated generic rules sit last so specific rules take precedence.
"""
import re
import math
from collections import Counter


def _entropy(s):
    """Shannon entropy of a string; high-entropy strings look like real secrets."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def looks_random(value, min_len=16, min_entropy=3.5):
    """Heuristic: long + high-entropy => probably a real credential, not a placeholder."""
    if len(value) < min_len:
        return False
    lowered = value.lower()
    # obvious placeholders / examples
    for junk in ("example", "placeholder", "xxx", "test", "dummy", "sample",
                 "changeme", "your_", "my_", "todo", "undefined", "null"):
        if junk in lowered:
            return False
    return _entropy(value) >= min_entropy


PATTERNS = [
    {
        "name": "aws-access-key-id",
        "regex": re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
        "severity": "CRITICAL",
        "description": "AWS access key ID. Pair with the secret key for full account access.",
    },
    {
        "name": "aws-secret-key-assignment",
        "regex": re.compile(r"(?i)(aws_secret|aws-secret|secret[_-]?access[_-]?key)\s*[:=]\s*['\"]([A-Za-z0-9/+=]{40})['\"]"),
        "severity": "CRITICAL",
        "description": "Probable AWS secret access key in an assignment.",
    },
    {
        "name": "google-api-key",
        "regex": re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b"),
        "severity": "HIGH",
        "description": "Google API key. Check which APIs it can call and whether referrer-restricted.",
    },
    {
        "name": "google-oauth-client-id",
        "regex": re.compile(r"\b([0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com)\b"),
        "severity": "MEDIUM",
        "description": "Google OAuth client ID. Useful for OAuth misconfiguration testing.",
    },
    {
        "name": "github-token",
        "regex": re.compile(r"\b((?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,})\b"),
        "severity": "CRITICAL",
        "description": "GitHub token. May grant repo/org access depending on scopes.",
    },
    {
        "name": "slack-token",
        "regex": re.compile(r"\b(xox[baprs]-[A-Za-z0-9\-]{10,})\b"),
        "severity": "HIGH",
        "description": "Slack token. Can read/post messages depending on scopes.",
    },
    {
        "name": "stripe-live-key",
        "regex": re.compile(r"\b((?:sk|rk)_live_[A-Za-z0-9]{16,})\b"),
        "severity": "CRITICAL",
        "description": "Stripe LIVE secret/restricted key. Publishable (pk_live) keys are lower risk.",
    },
    {
        "name": "stripe-test-key",
        "regex": re.compile(r"\b((?:sk|rk)_test_[A-Za-z0-9]{16,})\b"),
        "severity": "MEDIUM",
        "description": "Stripe test key. Lower risk, but shows key-handling hygiene.",
    },
    {
        "name": "private-key-block",
        "regex": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
        "severity": "CRITICAL",
        "description": "Private key material embedded in JavaScript. Full compromise of whatever it guards.",
    },
    {
        "name": "firebase-url",
        "regex": re.compile(r"https://([A-Za-z0-9\-]+\.firebaseio\.com)"),
        "severity": "MEDIUM",
        "description": "Firebase realtime DB URL. Test for world-readable/writable rules.",
    },
    {
        "name": "heroku-api-key",
        "regex": re.compile(r"\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b"),
        "severity": "HIGH",
        "description": "UUID-format token (Heroku-style API key). Verify before reporting.",
    },
    {
        "name": "jwt-token",
        "regex": re.compile(r"\b(eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})\b"),
        "severity": "MEDIUM",
        "description": "JWT. Decode it: check expiry, weak signing (none/HS256 confusion), sensitive claims.",
    },
    {
        "name": "generic-api-key-assignment",
        "regex": re.compile(r"(?i)(api[_-]?key|apikey|api[_-]?secret|client[_-]?secret)\s*[:=]\s*['\"]([^'\"]{16,})['\"]"),
        "severity": "MEDIUM",
        "description": "Generic API key/secret assignment. Entropy-gated to cut placeholders.",
        "entropy_gated": True,
    },
    {
        "name": "generic-token-assignment",
        "regex": re.compile(r"(?i)(auth[_-]?token|access[_-]?token|bearer)\s*[:=]\s*['\"]([^'\"]{20,})['\"]"),
        "severity": "MEDIUM",
        "description": "Generic auth/access token assignment. Entropy-gated to cut placeholders.",
        "entropy_gated": True,
    },
]


def scan_text(text):
    """Scan text for secrets. Returns list of finding dicts (deduplicated by value)."""
    findings = []
    seen = set()
    for pat in PATTERNS:
        for m in pat["regex"].finditer(text):
            # value is the last capture group (the secret itself, not the label)
            value = m.group(m.lastindex or 0)
            if not value or value in seen:
                continue
            if pat.get("entropy_gated") and not looks_random(value):
                continue
            seen.add(value)
            findings.append({
                "rule": pat["name"],
                "severity": pat["severity"],
                "description": pat["description"],
                # truncate long values in reports; full value kept for verification
                "preview": (value[:6] + "..." + value[-4:]) if len(value) > 16 else value,
                "value": value,
                "length": len(value),
            })
    return findings
