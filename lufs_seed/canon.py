"""Canonical JSON.

Signatures and content hashes are taken over bytes, so two implementations
must agree on the bytes exactly. The rules, deliberately boring:

  * keys sorted lexicographically (by unicode code point)
  * no insignificant whitespace  -> separators (",", ":")
  * UTF-8, no ASCII escaping of non-ASCII characters
  * NO FLOATS anywhere in a signed payload

That last rule is the one that bites people. Float formatting differs between
languages (and between Python versions), so a record signed here could fail to
verify in a JS reimplementation over a trailing digit. Every measurement in a
record is therefore carried as a preformatted *string* (e.g. "-96.42") or an
int. `assert_no_floats` enforces it rather than trusting authors to remember.
"""

import json

from .errors import LufsSeedError


def fmt_db(value: float) -> str:
    """Format a decibel measurement for a signed record: 2dp, as a string."""
    return f"{float(value):.2f}"


def fmt_ratio(value: float) -> str:
    """Format a unitless ratio / bits-per-sample estimate: 4dp, as a string."""
    return f"{float(value):.4f}"


def assert_no_floats(obj, path="$"):
    """Recursively refuse floats in a payload that is about to be signed."""
    if isinstance(obj, float):
        raise LufsSeedError(
            f"float found at {path} in a signed payload; format it with "
            "canon.fmt_db()/fmt_ratio() and carry it as a string"
        )
    if isinstance(obj, dict):
        for key, val in obj.items():
            if not isinstance(key, str):
                raise LufsSeedError(f"non-string key at {path}: {key!r}")
            assert_no_floats(val, f"{path}.{key}")
    elif isinstance(obj, (list, tuple)):
        for i, val in enumerate(obj):
            assert_no_floats(val, f"{path}[{i}]")


def dumps(obj) -> str:
    """Canonical JSON text."""
    assert_no_floats(obj)
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def encode(obj) -> bytes:
    """Canonical JSON bytes — the thing we hash and sign."""
    return dumps(obj).encode("utf-8")


def pretty(obj) -> str:
    """Human-facing rendering. Never hashed, never signed."""
    return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False)
