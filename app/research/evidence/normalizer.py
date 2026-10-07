"""Evidence normalization and secret redaction utilities for Phase 7.

Ensures that evidence content is normalized, structured, and sanitized
before storage and AI analysis.
"""

import re
from typing import List, Tuple


# Regex patterns for common credentials and secrets
SECRET_PATTERNS = [
    # Google API Keys
    (r"AIza[0-9A-Za-z\-_]{35}", "API_KEY", "[REDACTED_GOOGLE_API_KEY]"),
    # AWS Access Key IDs
    (r"\bAKIA[0-9A-Z]{16}\b", "AWS_KEY", "[REDACTED_AWS_KEY]"),
    # OpenAI API Keys (legacy sk-... and project sk-proj-...)
    (r"\bsk-(?:proj-)?[a-zA-Z0-9_\-]{20,}\b", "OPENAI_KEY", "[REDACTED_OPENAI_KEY]"),
    # GitHub Personal Access Tokens (ghp, gho, ghu, ghs, ghr)
    (r"\bgh[pousr]_[a-zA-Z0-9]{30,}\b", "GITHUB_TOKEN", "[REDACTED_GITHUB_TOKEN]"),
    # URI / Connection string credentials (e.g. postgres://user:pass@host)
    (r'(?i)(://[^:]+:)([^@\s/]{4,})(@)', "URI_CREDENTIAL", r"\1[REDACTED_PASSWORD]\3"),
    # Bearer Tokens
    (r"(?i)\bbearer\s+([a-zA-Z0-9_\-\.]{20,})\b", "BEARER_TOKEN", "Bearer [REDACTED_TOKEN]"),
    # Private Key blocks
    (r"-----BEGIN [A-Z\s]+PRIVATE KEY-----[^-]+-----END [A-Z\s]+PRIVATE KEY-----", "PRIVATE_KEY", "[REDACTED_PRIVATE_KEY]"),
    # Password key-value pairs
    (r'(?i)(["\']?(?:password|passwd|pwd|client_secret|secret)["\']?\s*[:=]\s*["\'])([^"\']{4,})(["\'])', "PASSWORD", r"\1[REDACTED_PASSWORD]\3"),
    # Session / Cookie IDs
    (r"(?i)\b((?:session|sessid|phpsessid|jsessionid|jwt)\s*=\s*)([a-zA-Z0-9_\-\.]{16,})", "SESSION_TOKEN", r"\1[REDACTED_SESSION]"),
    # Standalone JWT Strings
    (r"\beyJ[a-zA-Z0-9_\-]{10,}\.eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\b", "JWT_TOKEN", "[REDACTED_JWT]"),
]


def redact_secrets(text: str) -> Tuple[str, bool, List[str]]:
    """Scan and redact known secret/credential patterns from text.

    Returns:
        Tuple of (redacted_text, is_redacted, list_of_redaction_types)
    """
    if not text:
        return text, False, []

    redacted = text
    types_found: List[str] = []

    for pattern, label, replacement in SECRET_PATTERNS:
        if re.search(pattern, redacted):
            types_found.append(label)
            redacted = re.sub(pattern, replacement, redacted)

    is_redacted = len(types_found) > 0
    return redacted, is_redacted, list(set(types_found))


def clean_observation_statement(statement: str) -> str:
    """Ensure observation statements remain factual rather than speculative.

    An observation records WHAT WAS OBSERVED, not vulnerability conclusions.
    """
    cleaned = statement.strip()
    # Normalize excessive whitespace
    cleaned = re.sub(r"\s+", " ", cleaned)
    return cleaned
