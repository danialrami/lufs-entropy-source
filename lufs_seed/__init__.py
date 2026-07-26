"""lufs-seed — verifiable, provenanced seeds for process work.

This is NOT a "better random number generator". On raw unpredictability
`os.urandom` is unbeatable and we do not try. What this buys you is
*identity, reproducibility, portability and provenance* for the seed that
sits at the head of a generative process.

See docs/product/lufs-seed/ in danialrami/agent-knowledge for the why.
"""

__version__ = "0.1.0"

SPEC_VERSION = "lufs-seed/v1"

__all__ = ["__version__", "SPEC_VERSION"]
