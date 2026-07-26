"""Source registry — filesystem-as-registry's little sibling.

Adding a source (a TrueRNG, an RTL-SDR, a webcam sensor floor) means writing a
module here and adding one line to REGISTRY. Nothing else in the tool needs to
change: mint, verify and the record format are all source-agnostic.
"""

from .audio import AudioNoiseFloorSource, synthesise_noise_floor
from .base import Source, SourceResult, condition
from .jitter import HwRngSource, JitterSource, UrandomSource

REGISTRY = {
    AudioNoiseFloorSource.source_id: AudioNoiseFloorSource,
    JitterSource.source_id: JitterSource,
    HwRngSource.source_id: HwRngSource,
    UrandomSource.source_id: UrandomSource,
}

# Order matters: it is bound into the seed derivation, so it must be stable
# and it must be recorded. Sorted by source_id at combine time.
PHYSICAL_SOURCES = [
    AudioNoiseFloorSource.source_id,
    HwRngSource.source_id,
    JitterSource.source_id,
]

__all__ = [
    "REGISTRY",
    "PHYSICAL_SOURCES",
    "Source",
    "SourceResult",
    "condition",
    "AudioNoiseFloorSource",
    "JitterSource",
    "HwRngSource",
    "UrandomSource",
    "synthesise_noise_floor",
]
