"""The seed record — mint, verify, tiers.

Design crux, and the thing that makes verification meaningful:

    THE SEED IS PUBLIC AND CONTENT-ADDRESSED.

The record stores each source's 32-byte digest. The seed is HKDF over those
digests in a declared order. So `verify` does not take anybody's word for the
seed value — it RECOMPUTES it from the recorded digests and compares. And when
the audio artifact is present it recomputes the audio digest from the wav
itself, which binds the recording to the seed in a chain a third party can
walk end to end:

    recording bytes -> LSB stream -> audio digest -> seed -> signature

Change one sample of the wav and the audio digest moves, the seed moves, the
record no longer matches, and the signature fails. That is the property worth
having. It is the same shape as the Workchain catalog content hash, applied to
randomness.

The seed being public is not a weakness here. This is not key material. It is
the identified origin of a body of creative work, and it needs to be citable,
diffable and checkable by someone who is not you.

TIERS, mirroring Workchain:
  unverified  no physical source contributed (urandom only)
  verified    >=1 physical source, all gating checks passed, budget met
  certified   verified AND ed25519-signed
"""

import datetime
import platform
import socket

from . import canon, kdf, signing
from .errors import EntropyBudgetNotMet, SourceUnavailable, VerificationFailed
from .sources import REGISTRY

SPEC = "lufs-seed/v1"

# 256 bits of assessed min-entropy from physical sources. The audio floor
# clears this by two orders of magnitude; the number exists so that a
# marginal source cannot quietly carry a mint on its own.
DEFAULT_MIN_ENTROPY_BITS = 256.0

TIER_UNVERIFIED = "unverified"
TIER_VERIFIED = "verified"
TIER_CERTIFIED = "certified"


def _utc_now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def seed_id(seed_bytes):
    """`lufs-seed-<first 8 hex>` — deliberately parallel to the archive's
    `lufs-<first8>` catalog number, so the family resemblance is visible."""
    return "lufs-seed-" + seed_bytes.hex()[:8]


def build_payload(sources, seed_bytes, minted_at, tier, host, note,
                  entropy_bits, min_entropy_required):
    """The signable core of a record.

    Everything that affects the seed lives in here. The signature block wraps
    this and is never part of it.
    """
    payload = {
        "spec": SPEC,
        "seed_id": seed_id(seed_bytes),
        "seed_hex": seed_bytes.hex(),
        "minted_at": minted_at,
        "tier": tier,
        "host": host,
        "entropy": {
            "assessed_bits": canon.fmt_ratio(entropy_bits),
            "required_bits": canon.fmt_ratio(min_entropy_required),
            "note": ("assessed min-entropy from PHYSICAL sources only; "
                     "urandom contributes unpredictability but counts zero"),
        },
        "sources": sources,
        "derivation": {
            "combine": "HKDF-SHA256(ikm=concat(len||source_id||digest), "
                       "salt='lufs-seed/v1/combine', info='lufs-seed/v1/seed')",
            "order": [s["source_id"] for s in sources],
            "derive": "HKDF-Expand-SHA256(prk=seed, "
                      "info='lufs-seed/v1/derive/<label>')",
        },
    }
    if note:
        payload["note"] = note
    return payload


def recompute_seed(sources):
    """Rebuild the seed from the recorded digests. The core of verify."""
    digests = [(s["source_id"], bytes.fromhex(s["digest"])) for s in sources]
    return kdf.combine(digests)


def mint(source_specs, sign_key=None, note=None,
         min_entropy_bits=DEFAULT_MIN_ENTROPY_BITS, host=None, **source_kwargs):
    """Collect from sources, gate, combine, optionally sign.

    `source_specs` is a list of (source_id, required) pairs. A REQUIRED source
    that is unavailable or unhealthy raises — no silent substitution, ever.
    An OPTIONAL source that is unavailable is recorded as absent, with the
    reason, so the record says what did not happen as well as what did.
    """
    collected = []
    absent = []

    for source_id, required in source_specs:
        cls = REGISTRY.get(source_id)
        if cls is None:
            raise SourceUnavailable(f"unknown source: {source_id}")

        instance = cls(**source_kwargs.get(source_id, {}).get("init", {}))
        ok, reason = instance.available()
        if not ok:
            if required:
                raise SourceUnavailable(
                    f"required source '{source_id}' unavailable: {reason}"
                )
            absent.append({"source_id": source_id, "reason": reason})
            continue

        opts = dict(source_kwargs.get(source_id, {}).get("collect", {}))
        result = instance.collect(**opts)
        collected.append(result)

    if not collected:
        raise SourceUnavailable("no sources produced a digest")

    # Stable, declared order.
    collected.sort(key=lambda r: r.source_id)

    physical_bits = sum(r.entropy_bits for r in collected if r.physical)
    have_physical = any(r.physical for r in collected)

    if have_physical and physical_bits < min_entropy_bits:
        raise EntropyBudgetNotMet(
            f"assessed physical min-entropy {physical_bits:.1f} bits < "
            f"required {min_entropy_bits:.1f} bits. Record longer, or add a source."
        )

    seed_bytes = kdf.combine([(r.source_id, r.digest) for r in collected])

    source_records = []
    for r in collected:
        source_records.append({
            "source_id": r.source_id,
            "physical": r.physical,
            "digest": r.digest.hex(),
            "entropy_bits": canon.fmt_ratio(r.entropy_bits),
            "checks": [c.to_record() for c in r.checks],
            "detail": r.detail,
        })

    # Tier must be final BEFORE the payload is built, because tier lives
    # inside the signed payload. Signing something and then editing it is how
    # you end up with a signature over bytes nobody can reconstruct.
    if sign_key:
        tier = TIER_CERTIFIED
    elif have_physical:
        tier = TIER_VERIFIED
    else:
        tier = TIER_UNVERIFIED

    if sign_key and not have_physical:
        raise SourceUnavailable(
            "refusing to certify a seed with no physical source. A signature "
            "over urandom would be a signed claim of provenance we do not have."
        )

    payload = build_payload(
        sources=source_records,
        seed_bytes=seed_bytes,
        minted_at=_utc_now(),
        tier=tier,
        host=host or socket.gethostname(),
        note=note,
        entropy_bits=physical_bits,
        min_entropy_required=min_entropy_bits,
    )
    if absent:
        payload["absent_sources"] = sorted(absent, key=lambda a: a["source_id"])
    payload["platform"] = {
        "machine": platform.machine(),
        "system": platform.system(),
    }

    record = {"payload": payload}

    if sign_key:
        sig, pub = signing.sign(canon.encode(payload), sign_key)
        record["signature"] = {
            "algorithm": "ed25519",
            "public_key": pub,
            "signature": sig,
        }

    artifacts = {r.source_id: r.artifact for r in collected if r.artifact}
    return record, seed_bytes, artifacts


def verify(record, audio_path=None, expect_public_key=None):
    """Check a record end to end. Returns (ok, checks).

    Never raises on a bad record — a verification failure is data, not an
    exception. Raises only on a malformed input it cannot even inspect.
    """
    checks = []

    def add(name, ok, detail):
        checks.append({"name": name, "ok": bool(ok), "detail": detail})
        return ok

    if not isinstance(record, dict) or "payload" not in record:
        raise VerificationFailed("record has no payload")
    payload = record["payload"]

    add("spec", payload.get("spec") == SPEC,
        f"spec is {payload.get('spec')!r}, expected {SPEC!r}")

    sources = payload.get("sources") or []
    add("has_sources", bool(sources), f"{len(sources)} source(s) recorded")

    # 1. every gating health check that was recorded must have passed
    failed = []
    for s in sources:
        for c in s.get("checks", []):
            if c.get("gating") and not c.get("ok"):
                failed.append(f"{s['source_id']}/{c['name']}")
    add("health_checks", not failed,
        "all gating checks passed" if not failed
        else "failed: " + ", ".join(failed))

    # 2. the seed must be reproducible from the recorded digests
    seed_ok = False
    try:
        recomputed = recompute_seed(sources)
        seed_ok = recomputed.hex() == payload.get("seed_hex")
        add("seed_recomputes", seed_ok,
            "seed matches HKDF over recorded digests" if seed_ok
            else f"MISMATCH: recomputed {recomputed.hex()[:16]}... but record "
                 f"claims {str(payload.get('seed_hex'))[:16]}...")
        add("seed_id_matches", payload.get("seed_id") == seed_id(recomputed),
            f"seed_id {payload.get('seed_id')}")
    except (ValueError, KeyError, TypeError) as exc:
        add("seed_recomputes", False, f"could not recompute: {exc}")

    # 3. entropy budget
    ent = payload.get("entropy", {})
    try:
        assessed = float(ent.get("assessed_bits", 0))
        required = float(ent.get("required_bits", 0))
        has_physical = any(s.get("physical") for s in sources)
        add("entropy_budget", (not has_physical) or assessed >= required,
            f"{assessed:.1f} bits assessed vs {required:.1f} required")
    except (TypeError, ValueError):
        add("entropy_budget", False, "unparseable entropy block")

    # 4. tier consistency
    tier = payload.get("tier")
    has_physical = any(s.get("physical") for s in sources)
    signed = "signature" in record
    if tier == TIER_CERTIFIED:
        expected_ok = has_physical and signed
    elif tier == TIER_VERIFIED:
        expected_ok = has_physical
    else:
        expected_ok = not has_physical
    add("tier_consistent", expected_ok,
        f"tier={tier}, physical={has_physical}, signed={signed}")

    # 5. signature
    if signed:
        sig = record["signature"]
        payload_bytes = canon.encode(payload)
        valid = signing.verify(payload_bytes, sig.get("signature", ""),
                               sig.get("public_key", ""))
        add("signature", valid,
            f"ed25519 over canonical payload ({len(payload_bytes)} bytes)"
            if valid else "SIGNATURE INVALID — record has been altered")
        if expect_public_key:
            add("signer_identity", sig.get("public_key") == expect_public_key,
                "signer matches the expected key" if
                sig.get("public_key") == expect_public_key
                else "signed by a DIFFERENT key than expected")
    else:
        add("signature", True, "unsigned (tier below certified) — not an error")

    # 6. the strongest link: recompute the audio digest from the wav itself
    audio_src = next((s for s in sources
                      if s["source_id"] == "audio-noise-floor"), None)
    if audio_path and audio_src:
        # Two distinct bindings, and they check different things:
        #
        #   content_sha256 over the WHOLE file  -> provenance. Any edit to the
        #       recording at all, audible or not, breaks this.
        #   the LSB digest                      -> entropy. Proves the seed
        #       actually came out of this noise.
        #
        # Only the second feeds the seed (the entropy lives in the low bits,
        # not in the hum). But the first is inside the signed payload, so the
        # signature covers the exact file. Checking only the LSB digest would
        # let someone alter the upper bits — overwrite the audible content —
        # while the seed still "verified". Caught by
        # test_single_bit_change_in_the_recording_is_caught.
        import hashlib
        try:
            with open(audio_path, "rb") as fh:
                actual_sha = hashlib.sha256(fh.read()).hexdigest()
            claimed_sha = audio_src.get("detail", {}).get("content_sha256")
            add("audio_content_hash", actual_sha == claimed_sha,
                f"file sha256 matches the signed record ({actual_sha[:16]}...)"
                if actual_sha == claimed_sha else
                f"file sha256 {actual_sha[:16]}... does NOT match the recorded "
                f"{str(claimed_sha)[:16]}... — the recording has been altered")
        except OSError as exc:
            add("audio_content_hash", False, f"could not read {audio_path}: {exc}")

        try:
            from .sources.audio import AudioNoiseFloorSource
            lsb_bits = audio_src.get("detail", {}).get("lsb_bits", 8)
            re_result = AudioNoiseFloorSource(audio_path).collect(lsb_bits=lsb_bits)
            match = re_result.digest.hex() == audio_src["digest"]
            add("audio_artifact_binds", match,
                "recording reproduces the recorded audio digest — the wav, the "
                "seed and the signature are one chain" if match
                else "the supplied recording does NOT produce the recorded "
                     "digest; wrong file or altered audio")
        except Exception as exc:  # a failed re-derivation IS a verify failure
            add("audio_artifact_binds", False, f"could not re-derive: {exc}")
    elif audio_src:
        add("audio_artifact_binds", True,
            "recording not supplied (pass --audio to check the full chain)")

    ok = all(c["ok"] for c in checks)
    return ok, checks
