"""Approval binding hash (pure).

An approval is valid only for the exact tool and arguments it was granted for. We hash a
canonical JSON form so key order and whitespace cannot produce a different (or equal) hash
by accident. `approval_id` and `dry_run` are deliberately not part of the hashed arguments.
"""

import hashlib
import json
from typing import Any


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def args_hash(tool: str, args: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json({"tool": tool, "args": args}).encode()).hexdigest()
