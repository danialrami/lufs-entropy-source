"""lufs-seed CLI.

Agent-ergonomic by construction: --json on every subcommand, distinct exit
codes per failure class, no interactive prompts, no daemon, no network.

  keygen   create the ed25519 signing identity
  mint     collect entropy, gate it, emit a signed seed record   (rare)
  derive   expand a seed into bytes/floats/ints under a label    (constant)
  verify   recompute and check a record end to end
  show     summarise a record for a human
  sources  what this machine can actually offer
  selftest prove the install works, no hardware needed
"""

import argparse
import json
import os
import sys

from . import __version__, canon, kdf, record, signing
from .errors import LufsSeedError, UsageError
from .sources import PHYSICAL_SOURCES, REGISTRY


# --- helpers ---------------------------------------------------------------

def _emit(obj, as_json):
    if as_json:
        print(canon.pretty(obj))
    return obj


def _load_record(path):
    if not os.path.isfile(path):
        raise UsageError(f"no such record: {path}")
    with open(path) as fh:
        try:
            return json.load(fh)
        except json.JSONDecodeError as exc:
            raise UsageError(f"{path} is not valid JSON: {exc}")


def _resolve_seed(args):
    """Get seed bytes from --seed <hex> or --record <file>."""
    if args.seed:
        text = args.seed.strip()
        if text.startswith("lufs-seed-"):
            raise UsageError(
                "that is a seed_id, not the seed. Pass --record <file.json>, "
                "or --seed with the full 64-hex seed value."
            )
        try:
            raw = bytes.fromhex(text)
        except ValueError:
            raise UsageError("--seed must be 64 hex characters")
        if len(raw) != 32:
            raise UsageError(f"--seed must be 32 bytes (64 hex), got {len(raw)}")
        return raw, None
    if args.record:
        rec = _load_record(args.record)
        payload = rec.get("payload", {})
        # never trust the stored value; recompute from the digests
        computed = record.recompute_seed(payload.get("sources", []))
        if computed.hex() != payload.get("seed_hex"):
            raise LufsSeedError(
                f"{args.record}: the stored seed does not match its own source "
                "digests. Run `lufs-seed verify` — this record is not trustworthy."
            )
        return computed, rec
    raise UsageError("need --seed <hex> or --record <file.json>")


# --- subcommands -----------------------------------------------------------

def cmd_keygen(args):
    info = signing.generate_keypair(args.key, force=args.force)
    if args.json:
        _emit(info, True)
    else:
        print(f"signing key  {info['key_path']}  (mode 0600)")
        print(f"public key   {info['pub_path']}")
        print(f"             {info['public_key']}")
        print("\nBack this up. Seeds certified with it cannot be re-certified "
              "by a different key.")
    return 0


def cmd_sources(args):
    rows = []
    for source_id in sorted(REGISTRY):
        cls = REGISTRY[source_id]
        init = {"path": args.audio} if source_id == "audio-noise-floor" else {}
        instance = cls(**init)
        ok, reason = instance.available()
        rows.append({
            "source_id": source_id,
            "available": ok,
            "physical": cls.physical,
            "reason": reason,
            "description": cls.description,
        })

    if args.json:
        _emit({"sources": rows}, True)
    else:
        for row in rows:
            mark = "yes" if row["available"] else "no "
            kind = "physical" if row["physical"] else "non-physical"
            print(f"[{mark}] {row['source_id']:<20} ({kind})")
            print(f"      {row['description']}")
            if not row["available"]:
                print(f"      unavailable: {row['reason']}")
    return 0


def cmd_mint(args):
    specs = []
    kwargs = {}

    if args.audio:
        specs.append(("audio-noise-floor", True))
        kwargs["audio-noise-floor"] = {
            "init": {"path": args.audio},
            "collect": {
                "lsb_bits": args.lsb_bits,
                "floor_max_dbfs": args.floor_max_dbfs,
                "floor_min_dbfs": args.floor_min_dbfs,
                "min_duration_s": args.min_duration,
            },
        }

    if args.jitter:
        specs.append(("jitter", False))
        kwargs["jitter"] = {"collect": {"rounds": args.jitter_rounds}}

    if args.hwrng:
        specs.append(("hwrng", False))

    # urandom always participates: concatenate-and-hash means it can only
    # help, and it costs nothing. It never counts toward the budget.
    specs.append(("urandom", False))

    if not any(s for s, _ in specs if s in PHYSICAL_SOURCES):
        if not args.allow_unverified:
            raise UsageError(
                "no physical source requested, so this would mint an "
                "`unverified` seed with no provenance. Pass --audio <file.wav> "
                "(preferred), --jitter, or --hwrng. Use --allow-unverified only "
                "if you genuinely want a seed that claims nothing."
            )

    rec, seed_bytes, artifacts = record.mint(
        source_specs=specs,
        sign_key=args.sign,
        note=args.note,
        min_entropy_bits=args.min_entropy_bits,
        **kwargs,
    )

    out_path = args.out
    if out_path is None:
        out_path = rec["payload"]["seed_id"] + ".seed.json"
    if out_path != "-":
        with open(out_path, "w") as fh:
            fh.write(canon.pretty(rec) + "\n")

    payload = rec["payload"]
    if args.json:
        _emit({
            "seed_id": payload["seed_id"],
            "seed_hex": payload["seed_hex"],
            "tier": payload["tier"],
            "record_path": out_path,
            "entropy_bits": payload["entropy"]["assessed_bits"],
            "sources": [s["source_id"] for s in payload["sources"]],
            "artifacts": artifacts,
        }, True)
    else:
        print(f"seed        {payload['seed_id']}")
        print(f"tier        {payload['tier']}")
        print(f"entropy     {payload['entropy']['assessed_bits']} bits "
              f"(physical sources only; required "
              f"{payload['entropy']['required_bits']})")
        print(f"sources     {', '.join(s['source_id'] for s in payload['sources'])}")
        for src, path in artifacts.items():
            print(f"artifact    {src}: {path}")
        print(f"record      {out_path}")
        if payload["tier"] != record.TIER_CERTIFIED:
            print("\nUnsigned. `lufs-seed mint --sign <key>` to reach `certified`.")
    return 0


def cmd_derive(args):
    seed, _rec = _resolve_seed(args)

    if args.floats:
        values = kdf.derive_floats(seed, args.label, args.floats)
        out = {"label": args.label, "kind": "floats", "count": args.floats,
               "values": values}
    elif args.ints:
        if args.min is None or args.max is None:
            raise UsageError("--ints requires --min and --max")
        values = kdf.derive_ints(seed, args.label, args.ints, args.min, args.max)
        out = {"label": args.label, "kind": "ints", "count": args.ints,
               "min": args.min, "max": args.max, "values": values}
    else:
        raw = kdf.derive(seed, args.label, args.bytes)
        values = raw.hex()
        out = {"label": args.label, "kind": "bytes", "count": args.bytes,
               "hex": values}

    if args.json:
        print(json.dumps(out, indent=2))
    else:
        if args.floats or args.ints:
            for val in out["values"]:
                print(val)
        else:
            print(out["hex"])
    return 0


def cmd_verify(args):
    rec = _load_record(args.record)
    expect = None
    if args.expect_key:
        if os.path.isfile(args.expect_key):
            with open(args.expect_key) as fh:
                expect = fh.read().strip()
        else:
            expect = args.expect_key

    ok, checks = record.verify(rec, audio_path=args.audio, expect_public_key=expect)

    if args.json:
        _emit({"ok": ok, "seed_id": rec["payload"].get("seed_id"),
               "tier": rec["payload"].get("tier"), "checks": checks}, True)
    else:
        for check in checks:
            print(f"[{'PASS' if check['ok'] else 'FAIL'}] {check['name']}")
            print(f"       {check['detail']}")
        print()
        print("VERIFIED" if ok else "VERIFICATION FAILED")
    return 0 if ok else 6


def cmd_show(args):
    rec = _load_record(args.record)
    payload = rec["payload"]
    if args.json:
        _emit(rec, True)
        return 0

    print(f"{payload['seed_id']}   [{payload['tier']}]")
    print(f"  minted   {payload['minted_at']}  on {payload.get('host', '?')}")
    print(f"  seed     {payload['seed_hex']}")
    print(f"  entropy  {payload['entropy']['assessed_bits']} bits assessed")
    if payload.get("note"):
        print(f"  note     {payload['note']}")
    print("  sources:")
    for src in payload["sources"]:
        kind = "physical" if src["physical"] else "non-physical"
        print(f"    - {src['source_id']} ({kind}) {src['entropy_bits']} bits")
        detail = src.get("detail", {})
        if src["source_id"] == "audio-noise-floor":
            print(f"        recording  {detail.get('path')}")
            print(f"        catalog    {detail.get('catalog_number')}")
            print(f"        peak       {detail.get('peak_dbfs')} dBFS  "
                  f"rms {detail.get('rms_dbfs')} dBFS")
    for absent in payload.get("absent_sources", []):
        print(f"    - {absent['source_id']}: ABSENT ({absent['reason']})")
    if "signature" in rec:
        print(f"  signed by {rec['signature']['public_key']}")
    return 0


def cmd_selftest(args):
    """Prove the install is correct without any hardware."""
    import tempfile
    from .sources.audio import synthesise_noise_floor

    results = []

    def check(name, ok, detail):
        results.append({"name": name, "ok": bool(ok), "detail": detail})

    # RFC 5869 vectors — proves our HKDF is the real one, not our own dialect
    prk = kdf.hkdf_extract(bytes.fromhex("000102030405060708090a0b0c"),
                           bytes.fromhex("0b" * 22))
    okm = kdf.hkdf_expand(prk, bytes.fromhex("f0f1f2f3f4f5f6f7f8f9"), 42)
    check("rfc5869_tc1",
          okm.hex() == "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d"
                       "56ecc4c5bf34007208d5b887185865",
          "HKDF-SHA256 matches the published test vector")

    # determinism
    seed = bytes(range(32))
    check("derive_deterministic",
          kdf.derive(seed, "x", 64) == kdf.derive(seed, "x", 64),
          "same seed + label -> same bytes")
    check("label_independence",
          kdf.derive(seed, "a", 32) != kdf.derive(seed, "b", 32),
          "different labels -> different streams")
    check("prefix_property",
          kdf.derive(seed, "x", 64)[:32] == kdf.derive(seed, "x", 32),
          "a shorter draw is a prefix of a longer one")

    with tempfile.TemporaryDirectory() as tmp:
        wav = os.path.join(tmp, "floor.wav")
        synthesise_noise_floor(wav, seconds=6.0)
        specs = [("audio-noise-floor", True), ("jitter", False),
                 ("urandom", False)]
        rec, seed_bytes, _ = record.mint(
            source_specs=specs,
            sign_key=None,
            note="selftest (synthetic noise floor — NOT a real mint)",
            **{"audio-noise-floor": {"init": {"path": wav},
                                     "collect": {"min_duration_s": 5.0}},
               "jitter": {"collect": {"rounds": 512}}},
        )
        check("mint", rec["payload"]["tier"] == record.TIER_VERIFIED,
              f"minted {rec['payload']['seed_id']} at tier "
              f"{rec['payload']['tier']}")

        ok, _ = record.verify(rec, audio_path=wav)
        check("verify_roundtrip", ok, "record verifies against its own recording")

        tampered = json.loads(json.dumps(rec))
        tampered["payload"]["seed_hex"] = "00" * 32
        bad_ok, _ = record.verify(tampered)
        check("tamper_detected", not bad_ok,
              "a record with an altered seed fails verification")

    passed = all(r["ok"] for r in results)
    if args.json:
        _emit({"ok": passed, "checks": results}, True)
    else:
        for res in results:
            print(f"[{'PASS' if res['ok'] else 'FAIL'}] {res['name']}: {res['detail']}")
        print()
        print("SELFTEST OK" if passed else "SELFTEST FAILED")
    return 0 if passed else 1


# --- wiring ----------------------------------------------------------------

def build_parser():
    parser = argparse.ArgumentParser(
        prog="lufs-seed",
        description="Verifiable, provenanced seeds for process work. "
                    "Not a better RNG — a seed you can prove things about.",
    )
    parser.add_argument("--version", action="version",
                        version=f"lufs-seed {__version__} ({record.SPEC})")
    sub = parser.add_subparsers(dest="command", required=True)

    def add_json(p):
        p.add_argument("--json", action="store_true",
                       help="machine-readable output")

    p = sub.add_parser("keygen", help="create the ed25519 signing identity")
    p.add_argument("--key", default=signing.DEFAULT_KEY_PATH)
    p.add_argument("--force", action="store_true")
    add_json(p)
    p.set_defaults(func=cmd_keygen)

    p = sub.add_parser("sources", help="what this machine can offer")
    p.add_argument("--audio", help="a wav to test the audio source against")
    add_json(p)
    p.set_defaults(func=cmd_sources)

    p = sub.add_parser("mint", help="collect entropy and emit a seed record")
    p.add_argument("--audio", metavar="WAV",
                   help="preamp noise-floor recording (the flagship source)")
    p.add_argument("--jitter", action="store_true", help="include CPU timing jitter")
    p.add_argument("--jitter-rounds", type=int, default=4096)
    p.add_argument("--hwrng", action="store_true", help="include /dev/hwrng")
    p.add_argument("--lsb-bits", type=int, default=8,
                   help="how many low bits of each sample to harvest (default 8)")
    p.add_argument("--floor-max-dbfs", type=float, default=-30.0,
                   help="reject if peak is louder (a signal is present)")
    p.add_argument("--floor-min-dbfs", type=float, default=-110.0,
                   help="reject if peak is quieter (nothing captured)")
    p.add_argument("--min-duration", type=float, default=5.0)
    p.add_argument("--min-entropy-bits", type=float,
                   default=record.DEFAULT_MIN_ENTROPY_BITS)
    p.add_argument("--sign", metavar="KEY", nargs="?",
                   const=signing.DEFAULT_KEY_PATH,
                   help="sign the record -> tier `certified`")
    p.add_argument("--note", help="a human note stored in the record")
    p.add_argument("--out", help="record path (default <seed_id>.seed.json, - for stdout only)")
    p.add_argument("--allow-unverified", action="store_true",
                   help="permit a seed with no physical source")
    add_json(p)
    p.set_defaults(func=cmd_mint)

    p = sub.add_parser("derive", help="expand a seed under a label")
    p.add_argument("label", help="e.g. study-07/palette")
    p.add_argument("--record", help="seed record json")
    p.add_argument("--seed", help="raw 64-hex seed")
    p.add_argument("--bytes", type=int, default=32)
    p.add_argument("--floats", type=int, help="emit N floats in [0,1)")
    p.add_argument("--ints", type=int, help="emit N ints in [min,max]")
    p.add_argument("--min", type=int)
    p.add_argument("--max", type=int)
    add_json(p)
    p.set_defaults(func=cmd_derive)

    p = sub.add_parser("verify", help="recompute and check a record")
    p.add_argument("record")
    p.add_argument("--audio", help="the recording, to check the full chain")
    p.add_argument("--expect-key", help="public key (or path) the signer must match")
    add_json(p)
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("show", help="summarise a record")
    p.add_argument("record")
    add_json(p)
    p.set_defaults(func=cmd_show)

    p = sub.add_parser("selftest", help="prove the install works (no hardware)")
    add_json(p)
    p.set_defaults(func=cmd_selftest)

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except LufsSeedError as exc:
        if getattr(args, "json", False):
            print(json.dumps({"ok": False, "error": str(exc),
                              "error_type": type(exc).__name__}, indent=2))
        else:
            print(f"error: {exc}", file=sys.stderr)
        return exc.exit_code
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
