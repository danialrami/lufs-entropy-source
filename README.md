# lufs-seed

**Verifiable, provenanced seeds for process work.**

> This is not a better random number generator. On raw unpredictability
> `os.urandom` is unbeatable and we do not try to beat it. What this buys you
> is **identity, reproducibility, portability and provenance** for the seed
> that sits at the head of a generative process — and those are the four
> things a practice built on *authoring processes rather than outputs*
> actually needs.

A seed minted here is a named object with a signed record you can hand to
someone else, and they can check every claim in it without trusting you.

```
recording bytes -> LSB stream -> audio digest -> seed -> signature
```

Change one sample of the recording and the whole chain breaks. That is the
property worth having.

## Why this exists

Before this tool, `seed: 42` in a Score YAML meant nothing checkable. Worse,
"the same seed" did not even mean the same *stream* — Python's `random`,
JavaScript's `Math.random` and SuperCollider's RNG all produce different
output from identical seeds, so a "reproducible" process was only reproducible
inside one runtime.

`lufs-seed` fixes both halves:

| | before | after |
|---|---|---|
| identity | an integer somebody typed | `lufs-seed-a21dc5db`, content-addressed |
| reproducibility | hoped for | recomputed and asserted by `verify` |
| portability | three runtimes, three streams | one HMAC-SHA256 spec, byte-identical |
| provenance | none | ed25519-signed, bound to an archived recording |
| commitment | none | a signed timestamp proves the seed pre-existed the output |

That last row is the artistic one. A signed, timestamped seed proves you did
not roll a hundred and keep the pretty one. For a practice whose whole claim
is *"I authored the process, not the output,"* that turns the claim into
evidence.

## Install

Python 3.8+. No dependencies for minting and deriving; `cryptography` only if
you want to sign.

```bash
python3 -m pip install cryptography   # optional, for the certified tier
python3 -m lufs_seed.cli selftest     # proves the install, no hardware needed
```

## The sources

| source | physical? | what it is |
|---|---|---|
| `audio-noise-floor` | yes | Johnson–Nyquist thermal noise from your own preamp. The flagship. |
| `hwrng` | yes | `/dev/hwrng`, the SoC hardware RNG (present on the Pis). |
| `jitter` | yes\* | CPU timing jitter. \*Computational unpredictability from an unmodelable microarchitectural state — **not** thermal randomness. Degrades under virtualisation, and the record says so. |
| `urandom` | **no** | Kernel CSPRNG. Always mixed in, **never** counted toward the entropy budget: unbeatable unpredictability, zero provenance. |

Sources are combined by concatenate-and-hash, never by averaging or choosing.
The relevant property: **the result is at least as strong as the single best
contributor**, so adding a weak source can never weaken the seed.

### The audio noise floor

Turn the preamp up with nothing plugged in (or better, with the input
terminated) and record the hiss. At high gain the bottom bits of a 24-bit
converter are dominated by thermal noise — genuinely physical, genuinely
unpredictable, from a converter you already own and have more reason to trust
than a $50 USB dongle.

The health gate is two-sided, and that is the interesting part:

- **too loud** → something is plugged in; you would be seeding from a *signal*,
  which may be known to someone else. Fail.
- **too quiet** → muted input or dead converter; there is no noise to harvest.
  Fail.

20 seconds at 48k yields millions of assessed min-entropy bits against a
256-bit requirement, so duration is set by wanting a decent health-test window
and a keepable artifact, not by the math.

## Usage

Mint rarely. Derive constantly.

```bash
# once per session, or per body of work
lufs-seed keygen
lufs-seed mint --audio floor.wav --jitter --sign \
    --note "kitchen preamp, nothing plugged in"

# constantly: free, offline, deterministic
lufs-seed derive "study-07/palette" --record lufs-seed-a21dc5db.seed.json --floats 4
lufs-seed derive "study-07/pitches" --record lufs-seed-a21dc5db.seed.json --ints 12 --min 0 --max 6

# anyone can check the whole chain
lufs-seed verify lufs-seed-a21dc5db.seed.json --audio floor.wav
```

One mint feeds unlimited independent streams: two different labels give
streams that cannot be distinguished from independent, so every render,
palette, voice and layer takes its own label off the same seed and none of
them correlate. **You never mint per-render.**

There is no daemon and no network. A service in the middle of a local creative
pipeline is an availability dependency, and that is against local-first.

## Tiers

Mirrors the Workchain certification ladder:

- **unverified** — no physical source contributed (`urandom` only).
- **verified** — at least one physical source, all gating health checks
  passed, entropy budget met.
- **certified** — verified *and* ed25519-signed.

The tool **refuses to certify a seed with no physical source**: a signature
over `urandom` would be a signed claim of provenance we do not have.

## Verification

`verify` does not take the record's word for anything. It recomputes the seed
from the recorded per-source digests, re-derives the audio digest from the wav
itself, and checks the signature over canonical bytes.

Two distinct bindings on the recording, doing different jobs:

- `content_sha256` over the whole file — **provenance**. Any edit at all breaks it.
- the LSB digest — **entropy**. Proves the seed came out of this noise.

Only the second feeds the seed. Both are inside the signed payload, so editing
the audible upper bits of the recording while leaving the noise floor intact is
caught by the first. (There is a test for exactly this.)

## Portability

`contrib/lufs-seed-derive.mjs` is a dependency-free JavaScript port of the
derivation half, for browser-side rendering. `tests/fixtures/derivation-vectors.json`
is generated by the Python implementation, and `tests/check_js_vectors.mjs`
asserts the port reproduces it byte for byte — including the 8160-byte chunking
boundary and float bit-exactness. If the two ever disagree, CI fails.

The spec is HMAC-SHA256 and nothing else, deliberately: a faithful
reimplementation is ~60 lines in any language with a standard library, so
SuperCollider is a straightforward next port.

## Verifiable correctness

```bash
python3 -m pytest tests/ -q          # 67 tests
node tests/check_js_vectors.mjs      # 12 cross-language vectors
python3 -m lufs_seed.cli selftest    # end-to-end, no hardware
```

The HKDF core is checked against the published **RFC 5869** test vectors, so it
is standards-correct rather than merely self-consistent. Health tests follow
**NIST SP 800-90B** (repetition count, adaptive proportion, and the
conservative most-common-value min-entropy estimator — chosen because it
under-reports a good source and cannot be talked into over-reporting a bad
one).

## Exit codes

| code | meaning |
|---|---|
| 0 | success |
| 2 | usage error |
| 3 | a required source was unavailable |
| 4 | a health check failed |
| 5 | entropy budget not met |
| 6 | verification failed |
| 7 | signing/key error |

## History

This repo began in January 2026 as `EntropyOrchestrator`: an asyncio service
serving hardware RNG over HTTP, WebSocket and OSC. It never ran — `python_osc`
is not the module name — and it had **four silent `os.urandom` fallbacks**, so
a consumer could never tell whether bytes came from hardware or the kernel. A
service whose entire value proposition is provenance, lying about provenance,
is the purest form of *exit 0 but wrong*.

The rewrite keeps the good instinct (self-owned entropy is worth having) and
throws out the framing (more randomness, served faster). Nothing here falls
back. Ever.
