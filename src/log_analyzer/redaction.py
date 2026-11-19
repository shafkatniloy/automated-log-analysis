import re
from typing import List, Tuple

DEFAULT_REDACTION_PATTERNS: List[Tuple[str, str]] = [
    (r"(?i)\b(bearer\s+)[a-zA-Z0-9_\-\.]{15,}\b", r"\1[REDACTED]"),
    (
        r'(?i)(password["\']?\s*[:=]\s*["\']?)([^"\'\s,;]+)(["\']?)',
        r"\1[REDACTED]\3",
    ),
    (
        r'(?i)(api[_-]?key["\']?\s*[:=]\s*["\']?)([a-zA-Z0-9_\-]{16,})(["\']?)',
        r"\1[REDACTED]\3",
    ),
    (
        r"-----BEGIN [A-Z ]+ PRIVATE KEY-----[^-]+-----END [A-Z ]+ PRIVATE KEY-----",
        "[REDACTED_PRIVATE_KEY]",
    ),
]


def redact_secrets(
    text: str, patterns: List[Tuple[str, str]] = DEFAULT_REDACTION_PATTERNS
) -> str:
    if not text:
        return text

    sanitized = text
    for pattern, replacement in patterns:
        sanitized = re.sub(pattern, replacement, sanitized)
    return sanitized


def sanitize_snippet(raw_line: str, max_length: int = 120) -> str:
    cleaned = raw_line.strip()
    redacted = redact_secrets(cleaned)
    if len(redacted) > max_length:
        return redacted[: max_length - 3] + "..."
    return redacted
