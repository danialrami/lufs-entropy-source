"""Timing-jitter and kernel sources — the no-hardware path.

Three distinct things live here and the difference between them matters,
because two of them make a physical claim and one does not.

`jitter` — times a fixed block of memory-and-hash work with a nanosecond
    clock, over and over, and harvests the variation in how long it takes.
    The variation comes from cache state, DRAM refresh, bus contention,
    branch prediction, interrupts, thermal/DVFS clock drift and other cores.
    Be precise about the claim: this is DETERMINISTIC IN PRINCIPLE. If you
    knew the complete microarchitectural state you could predict it. It is
    unpredictable because that state is enormous, unobservable and stirred
    continuously by physical processes — computational unpredictability from
    an unmodelable system, not thermal randomness. A weaker claim than the
    audio floor, and the record says so.

    It also degrades badly under timer virtualisation, which specifically
    means a cloud VM is the node to trust it on least. We record whether we
    appear to be virtualised so the reader can judge.

`hwrng` — /dev/hwrng, a real hardware RNG exposed by the SoC (the Pis have
    one). Physical. Absent on most machines, hence optional.

`urandom` — the kernel CSPRNG. NOT a physical source and never counted toward
    the entropy budget. It is included unconditionally as a floor, because
    concatenate-and-hash means an extra input can never weaken the seed, and
    on unpredictability alone os.urandom is already unbeatable. What it cannot
    give us is provenance, which is the entire reason the other sources exist.
"""

import hashlib
import os
import platform
import struct
import time

from .. import health
from ..canon import fmt_ratio
from ..errors import HealthCheckFailed
from .base import Source, SourceResult, condition

DEFAULT_ROUNDS = 4096


def _looks_virtualised():
    """Best-effort. Advisory only, never gating."""
    try:
        for path in ("/sys/class/dmi/id/product_name", "/sys/class/dmi/id/sys_vendor"):
            if os.path.isfile(path):
                with open(path) as fh:
                    val = fh.read().strip().lower()
                for needle in ("kvm", "qemu", "vmware", "virtualbox", "xen",
                               "hyper-v", "microsoft corporation", "amazon", "google"):
                    if needle in val:
                        return True, val
        if os.path.isfile("/proc/cpuinfo"):
            with open("/proc/cpuinfo") as fh:
                if "hypervisor" in fh.read().lower():
                    return True, "hypervisor flag in /proc/cpuinfo"
    except OSError:
        pass
    return False, "no virtualisation markers found"


class JitterSource(Source):
    source_id = "jitter"
    physical = True
    description = "CPU timing jitter (memory + hash work timed with a ns clock)"

    def available(self):
        if not hasattr(time, "perf_counter_ns"):
            return False, "no nanosecond clock available"
        return True, "ok"

    def collect(self, rounds=DEFAULT_ROUNDS, **_):
        self.require()

        deltas = []
        buf = bytearray(64 * 1024)
        acc = hashlib.sha256(b"lufs-seed/jitter")
        for i in range(rounds):
            t0 = time.perf_counter_ns()
            # touch memory in a way the compiler cannot elide, then hash it
            for off in range(0, len(buf), 4096):
                buf[off] = (buf[off] + i + off) & 0xFF
            acc.update(bytes(buf[:1024]))
            acc.update(struct.pack("<Q", t0))
            t1 = time.perf_counter_ns()
            deltas.append(t1 - t0)

        # The entropy is in the LOW bits of each delta. The high bits are the
        # deterministic cost of the work we just did and carry nothing.
        lsb = [d & 0xFF for d in deltas]

        checks, h_per, total = health.assess(lsb, "timing delta low byte", window=256)

        virt, virt_detail = _looks_virtualised()
        checks.append(health.CheckResult(
            "not_virtualised",
            not virt,
            f"virtualisation: {virt_detail} — timer jitter is less trustworthy "
            "under a hypervisor" if virt else virt_detail,
            False,  # advisory, not gating
        ))

        failures = [c for c in checks if c.gating and not c.ok]
        if failures:
            raise HealthCheckFailed(
                "jitter source rejected:\n"
                + "\n".join(f"  - {c.name}: {c.detail}" for c in failures)
            )

        packed = b"".join(struct.pack("<q", d) for d in deltas)
        digest = condition(packed + acc.digest(), "jitter")

        return SourceResult(
            source_id=self.source_id,
            digest=digest,
            checks=checks,
            entropy_bits=total,
            physical=True,
            detail={
                "rounds": rounds,
                "platform": platform.machine(),
                "virtualised": bool(virt),
                "min_entropy_bits_per_sample": fmt_ratio(h_per),
                "min_entropy_bits_total": fmt_ratio(total),
                "claim": ("computational unpredictability from an unmodelable "
                          "microarchitectural state; NOT thermal randomness"),
            },
        )


class HwRngSource(Source):
    source_id = "hwrng"
    physical = True
    description = "/dev/hwrng — SoC hardware RNG"

    PATH = "/dev/hwrng"

    def available(self):
        if not os.path.exists(self.PATH):
            return False, f"{self.PATH} not present"
        if not os.access(self.PATH, os.R_OK):
            return False, f"{self.PATH} not readable (needs group access)"
        return True, "ok"

    def collect(self, nbytes=4096, **_):
        self.require()
        with open(self.PATH, "rb") as fh:
            raw = fh.read(nbytes)
        if len(raw) < nbytes:
            raise HealthCheckFailed(
                f"{self.PATH} returned {len(raw)} of {nbytes} bytes"
            )

        checks, h_per, total = health.assess(list(raw), "hwrng byte", window=512)
        failures = [c for c in checks if c.gating and not c.ok]
        if failures:
            raise HealthCheckFailed(
                "hwrng rejected:\n"
                + "\n".join(f"  - {c.name}: {c.detail}" for c in failures)
            )

        return SourceResult(
            source_id=self.source_id,
            digest=condition(raw, "hwrng"),
            checks=checks,
            entropy_bits=total,
            physical=True,
            detail={
                "device": self.PATH,
                "bytes_read": len(raw),
                "min_entropy_bits_per_sample": fmt_ratio(h_per),
                "min_entropy_bits_total": fmt_ratio(total),
            },
        )


class UrandomSource(Source):
    source_id = "urandom"
    physical = False
    description = "kernel CSPRNG — unbeatable unpredictability, zero provenance"

    def available(self):
        return True, "ok"

    def collect(self, nbytes=64, **_):
        raw = os.urandom(nbytes)
        # No health tests: a CSPRNG passes every statistical test by
        # construction, so running them would be theatre. We assert what is
        # actually true about it instead.
        checks = [health.CheckResult(
            "is_not_physical",
            True,
            "kernel CSPRNG: contributes unpredictability but NO provenance; "
            "never counted toward the entropy budget",
            False,
        )]
        return SourceResult(
            source_id=self.source_id,
            digest=condition(raw, "urandom"),
            checks=checks,
            entropy_bits=0.0,   # deliberately zero
            physical=False,
            detail={"bytes_read": nbytes},
        )
