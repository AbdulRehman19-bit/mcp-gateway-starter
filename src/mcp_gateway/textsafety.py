"""Untrusted-text hygiene (pure).

Third-party text (GitHub issues, comment bodies, database content) can hide instructions in
characters a human reviewer cannot see: bidi overrides (U+202E), zero-width characters (U+200B),
Unicode "tag" characters (U+E0000-E007F), C1 controls. We either strip them (text returned to
the AI client) or make them visible as <U+XXXX> (text shown to an approver, who must see exactly
what they are approving). Newline and tab are kept.
"""

import unicodedata
from typing import Any

_KEEP = frozenset("\n\t")
# Cc control, Cf format (bidi, zero-width, tags), Cs surrogate, Co private use
_INVISIBLE_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co"})


def _invisible(ch: str) -> bool:
    return ch not in _KEEP and unicodedata.category(ch) in _INVISIBLE_CATEGORIES


def strip_invisible(text: str) -> str:
    return "".join(ch for ch in text if not _invisible(ch))


def escape_invisible(text: str) -> str:
    """Make hidden characters visible, e.g. U+202E -> '<U+202E>'."""
    return "".join(f"<U+{ord(ch):04X}>" if _invisible(ch) else ch for ch in text)


def escape_invisible_deep(value: Any) -> Any:
    """Apply escape_invisible to every string (keys and values) in a JSON-like structure."""
    if isinstance(value, str):
        return escape_invisible(value)
    if isinstance(value, dict):
        return {escape_invisible_deep(k): escape_invisible_deep(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [escape_invisible_deep(v) for v in value]
    return value
