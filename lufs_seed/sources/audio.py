"""The flagship source: a preamp noise-floor recording.

The physics: Johnson-Nyquist thermal noise across the input impedance —
electrons jittering because the resistor is above absolute zero — plus shot
noise across semiconductor junctions. At high preamp gain the bottom bits of a
24-bit converter are dominated by it. That is a genuine physical entropy
source in the same class as a TrueRNG, using a converter you already own and
have more reason to trust than a $50 dongle.

Why we take only the low bits: the full sample word is mostly *structure* —
mains hum, supply spurs, the 1/f tilt, band-limiting from the anti-alias
filter. All of that is predictable and none of it is entropy. The LSBs are
where the thermal noise lives. We assess the LSBs, and we condition with
SHA-256 so the residual structure cannot survive into the digest.

The health gate is two-sided and that is the interesting part:

  too loud  -> something is plugged in; you are seeding from a *signal*, and a
               signal is potentially known to someone else. FAIL.
  too quiet -> muted input, dead converter, or a digital-black file. There is
               no thermal noise to harvest. FAIL.

The recording is kept. It is the provenance artifact: 20 seconds of your room's
electronics, content-hashed, and citable by catalog number. Your entropy source
produces a field recording.
"""

import hashlib
import os
import struct
import wave

from .. import health
from ..canon import fmt_db, fmt_ratio
from ..errors import HealthCheckFailed
from .base import Source, SourceResult, condition

# Gate thresholds in dBFS peak. A working preamp with nothing plugged in and
# healthy gain sits well inside this band; a live signal blows past the top and
# a muted or digitally-black input falls under the bottom.
DEFAULT_FLOOR_MAX_DBFS = -30.0   # louder than this => a signal is present
DEFAULT_FLOOR_MIN_DBFS = -110.0  # quieter than this => nothing is being captured

DEFAULT_LSB_BITS = 8
DEFAULT_MIN_DURATION_S = 5.0


def _read_wav(path):
    """Read a PCM wav into a list of ints, plus its parameters.

    stdlib `wave` only — no numpy, no soundfile. This has to run on a Pi with
    nothing installed.
    """
    with wave.open(path, "rb") as wf:
        channels = wf.getnchannels()
        sampwidth = wf.getsampwidth()
        rate = wf.getframerate()
        nframes = wf.getnframes()
        raw = wf.readframes(nframes)

    if sampwidth not in (2, 3, 4):
        raise HealthCheckFailed(
            f"unsupported sample width {sampwidth * 8}-bit; need 16, 24 or 32"
        )

    samples = []
    if sampwidth == 2:
        count = len(raw) // 2
        samples = list(struct.unpack("<%dh" % count, raw[: count * 2]))
        full_scale = 1 << 15
    elif sampwidth == 3:
        for i in range(0, len(raw) - 2, 3):
            val = raw[i] | (raw[i + 1] << 8) | (raw[i + 2] << 16)
            if val & 0x800000:
                val -= 1 << 24
            samples.append(val)
        full_scale = 1 << 23
    else:
        count = len(raw) // 4
        samples = list(struct.unpack("<%di" % count, raw[: count * 4]))
        full_scale = 1 << 31

    return {
        "samples": samples,
        "channels": channels,
        "sampwidth": sampwidth,
        "rate": rate,
        "frames": nframes,
        "full_scale": full_scale,
    }


def _peak_dbfs(samples, full_scale):
    if not samples:
        return -float("inf")
    peak = max(abs(s) for s in samples)
    if peak == 0:
        return -float("inf")
    import math
    return 20.0 * math.log10(peak / float(full_scale))


def _rms_dbfs(samples, full_scale):
    if not samples:
        return -float("inf")
    import math
    acc = 0.0
    for s in samples:
        acc += float(s) * float(s)
    rms = math.sqrt(acc / len(samples))
    if rms <= 0.0:
        return -float("inf")
    return 20.0 * math.log10(rms / float(full_scale))


class AudioNoiseFloorSource(Source):
    source_id = "audio-noise-floor"
    physical = True
    description = "Johnson-Nyquist thermal noise from an open/terminated preamp input"

    def __init__(self, path=None):
        self.path = path

    def available(self):
        if not self.path:
            return False, "no recording supplied (pass --audio <file.wav>)"
        if not os.path.isfile(self.path):
            return False, f"file not found: {self.path}"
        return True, "ok"

    def collect(self, floor_max_dbfs=DEFAULT_FLOOR_MAX_DBFS,
                floor_min_dbfs=DEFAULT_FLOOR_MIN_DBFS,
                lsb_bits=DEFAULT_LSB_BITS,
                min_duration_s=DEFAULT_MIN_DURATION_S,
                **_):
        self.require()

        info = _read_wav(self.path)
        samples = info["samples"]
        rate = info["rate"] or 1
        duration = info["frames"] / float(rate)

        with open(self.path, "rb") as fh:
            file_sha = hashlib.sha256(fh.read()).hexdigest()

        checks = []

        # --- duration -----------------------------------------------------
        checks.append(health.CheckResult(
            "duration",
            duration >= min_duration_s,
            f"{fmt_ratio(duration)}s (minimum {fmt_ratio(min_duration_s)}s)",
            True,
        ))

        # --- two-sided level gate ----------------------------------------
        peak = _peak_dbfs(samples, info["full_scale"])
        rms = _rms_dbfs(samples, info["full_scale"])
        peak_s = "-inf" if peak == -float("inf") else fmt_db(peak)
        rms_s = "-inf" if rms == -float("inf") else fmt_db(rms)

        checks.append(health.CheckResult(
            "not_a_signal",
            peak <= floor_max_dbfs,
            f"peak {peak_s} dBFS must be <= {fmt_db(floor_max_dbfs)} — "
            "louder means something is plugged in and you are seeding from a signal",
            True,
        ))
        checks.append(health.CheckResult(
            "floor_present",
            peak >= floor_min_dbfs and peak != -float("inf"),
            f"peak {peak_s} dBFS must be >= {fmt_db(floor_min_dbfs)} — "
            "quieter means a muted input or a dead converter, so there is no noise to harvest",
            True,
        ))

        # --- entropy lives in the low bits --------------------------------
        mask = (1 << lsb_bits) - 1
        lsb = [s & mask for s in samples]

        checks.append(health.CheckResult(
            "sample_count",
            len(lsb) >= 4096,
            f"{len(lsb)} samples (need >= 4096 for a meaningful assessment)",
            True,
        ))

        h_checks, h_per_sample, total_bits = health.assess(
            lsb, f"low {lsb_bits} bits", window=512
        )
        checks.extend(h_checks)

        failures = [c for c in checks if c.gating and not c.ok]
        if failures:
            raise HealthCheckFailed(
                "audio noise floor rejected:\n"
                + "\n".join(f"  - {c.name}: {c.detail}" for c in failures)
            )

        # Condition over the LSB stream, not the whole file, so the digest is
        # a function of the noise rather than of the hum riding on top of it.
        packed = b"".join(struct.pack("<H", v) for v in lsb)
        digest = condition(packed, "audio-noise-floor")

        detail = {
            "path": os.path.basename(self.path),
            "content_sha256": file_sha,
            "catalog_number": "lufs-" + file_sha[:8],
            "sample_rate": rate,
            "channels": info["channels"],
            "bit_depth": info["sampwidth"] * 8,
            "frames": info["frames"],
            "duration_s": fmt_ratio(duration),
            "peak_dbfs": peak_s,
            "rms_dbfs": rms_s,
            "lsb_bits": lsb_bits,
            "min_entropy_bits_per_sample": fmt_ratio(h_per_sample),
            "min_entropy_bits_total": fmt_ratio(total_bits),
        }

        return SourceResult(
            source_id=self.source_id,
            digest=digest,
            checks=checks,
            entropy_bits=total_bits,
            physical=True,
            detail=detail,
            artifact=self.path,
        )


def synthesise_noise_floor(path, seconds=20.0, rate=48000, bit_depth=24,
                           target_rms_dbfs=-78.0, hum_dbfs=-72.0, rng=None):
    """Write a realistic fake noise-floor wav. TESTING ONLY.

    Models what a real preamp floor looks like so the gate can be exercised
    without hardware: broadband noise at a plausible level, plus 60 Hz mains
    hum and a couple of harmonics *above* the noise, plus a slight 1/f tilt.
    The hum is deliberately louder than the noise because that is the real
    situation, and it is what proves the LSB-plus-conditioning approach works
    rather than merely passing on clean input.

    This is a test fixture generator and it is named so nobody mistakes its
    output for a real mint. `lufs-seed mint` will not call it.
    """
    import math
    import random

    rng = rng or random.Random(0xC1A11)
    full_scale = (1 << (bit_depth - 1)) - 1
    n = int(seconds * rate)

    noise_amp = full_scale * (10.0 ** (target_rms_dbfs / 20.0))
    hum_amp = full_scale * (10.0 ** (hum_dbfs / 20.0))

    prev = 0.0
    samples = []
    for i in range(n):
        white = rng.gauss(0.0, 1.0)
        # one-pole lowpass -> gentle 1/f-ish tilt
        prev = 0.85 * prev + 0.15 * white
        val = noise_amp * (0.6 * white + 0.4 * prev * 2.5)
        t = i / float(rate)
        val += hum_amp * math.sin(2.0 * math.pi * 60.0 * t)
        val += hum_amp * 0.4 * math.sin(2.0 * math.pi * 120.0 * t)
        val += hum_amp * 0.2 * math.sin(2.0 * math.pi * 180.0 * t)
        iv = int(max(-full_scale, min(full_scale, val)))
        samples.append(iv)

    sampwidth = bit_depth // 8
    with wave.open(path, "wb") as wf:
        wf.setnchannels(1)
        wf.setsampwidth(sampwidth)
        wf.setframerate(rate)
        if sampwidth == 3:
            buf = bytearray()
            for s in samples:
                u = s & 0xFFFFFF
                buf += bytes((u & 0xFF, (u >> 8) & 0xFF, (u >> 16) & 0xFF))
            wf.writeframes(bytes(buf))
        elif sampwidth == 2:
            wf.writeframes(struct.pack("<%dh" % len(samples), *samples))
        else:
            wf.writeframes(struct.pack("<%di" % len(samples), *samples))
    return path
