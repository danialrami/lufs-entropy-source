"""Source contract.

A source does exactly one thing: produce a 32-byte digest plus an honest,
signable account of where it came from. It never falls back. If it cannot do
its job it raises, and the mint either drops it (when it was optional) or
fails (when it was requested).
"""

import hashlib

from ..errors import SourceUnavailable


class SourceResult:
    """What a source hands back to the mint.

    digest       32 bytes, already conditioned
    checks       list[CheckResult]
    entropy_bits assessed min-entropy contributed (0 for non-physical sources)
    physical     True if the unpredictability comes from a physical process
    detail       dict of signable, float-free metadata for the record
    artifact     optional path to a file that should be retained as evidence
    """

    def __init__(self, source_id, digest, checks, entropy_bits,
                 physical, detail=None, artifact=None):
        if len(digest) != 32:
            raise ValueError(f"{source_id}: digest must be 32 bytes")
        self.source_id = source_id
        self.digest = digest
        self.checks = list(checks)
        self.entropy_bits = float(entropy_bits)
        self.physical = bool(physical)
        self.detail = detail or {}
        self.artifact = artifact

    @property
    def healthy(self):
        return all(c.ok for c in self.checks if c.gating)

    def failures(self):
        return [c for c in self.checks if c.gating and not c.ok]


class Source:
    """Base class. Subclasses implement `available()` and `collect()`."""

    source_id = "base"
    physical = False
    description = ""

    def available(self):
        """(bool, reason) — can this source run on this machine right now?"""
        return False, "not implemented"

    def collect(self, **kwargs):
        raise NotImplementedError

    def require(self):
        ok, reason = self.available()
        if not ok:
            raise SourceUnavailable(f"{self.source_id}: {reason}")


def condition(raw, domain):
    """Compress raw source bytes to a 32-byte digest.

    A hash is a randomness extractor: given enough min-entropy in the input,
    the output is computationally indistinguishable from uniform even when the
    input is badly non-uniform. This is what lets us take mains-hum-riddled,
    1/f-tilted, band-limited audio and still end up with a usable digest —
    provided the health tests confirmed the entropy was actually in there.
    The gate does the honest work; the hash just tidies up.

    `domain` separates sources so the same bytes read twice through different
    paths cannot produce the same digest.
    """
    h = hashlib.sha256()
    h.update(b"lufs-seed/v1/condition/")
    h.update(domain.encode("utf-8"))
    h.update(b"\x00")
    h.update(raw)
    return h.digest()
