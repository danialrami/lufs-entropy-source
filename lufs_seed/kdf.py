"""The portable derivation core — HKDF-SHA256 plus a counter-mode stream.

This module is the actual product. The entropy story is what makes a seed
*ours*; this file is what makes a seed *useful*, because it is the one piece
that must produce byte-identical output in Python, JavaScript and
SuperCollider.

Everything here is HMAC-SHA256 and nothing else. That is a deliberate
constraint: HMAC-SHA256 exists in the standard library of every runtime we
care about, so a faithful reimplementation is ~40 lines and needs no
dependency. ChaCha20 would be marginally faster and is a genuinely better
stream cipher, but "a colleague can reimplement this correctly in an
afternoon" beats "marginally faster" for a tool whose entire job is agreement
across runtimes.

  combine : seed  = HKDF(ikm = concat(source digests), salt, info)
  derive  : bytes = HKDF-Expand-style CTR stream over (seed, label)

RFC 5869 for HKDF. The expand step here IS RFC 5869 expand, so a third party
can check us against the RFC test vectors rather than against our own say-so.
"""

import hashlib
import hmac

HASH = hashlib.sha256
HASH_LEN = 32

# Domain separation. Anything that changes the meaning of the bytes must
# change these strings, so a v2 can never collide with a v1.
COMBINE_SALT = b"lufs-seed/v1/combine"
COMBINE_INFO = b"lufs-seed/v1/seed"
DERIVE_INFO_PREFIX = b"lufs-seed/v1/derive"


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """RFC 5869 section 2.2."""
    if not salt:
        salt = b"\x00" * HASH_LEN
    return hmac.new(salt, ikm, HASH).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 section 2.3."""
    if length < 0:
        raise ValueError("length must be non-negative")
    if length > 255 * HASH_LEN:
        raise ValueError(f"length must be <= {255 * HASH_LEN} bytes for SHA-256")
    out = bytearray()
    block = b""
    counter = 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), HASH).digest()
        out.extend(block)
        counter += 1
    return bytes(out[:length])


def hkdf(ikm: bytes, salt: bytes, info: bytes, length: int = HASH_LEN) -> bytes:
    return hkdf_expand(hkdf_extract(salt, ikm), info, length)


def combine(digests) -> bytes:
    """Fold per-source digests into the 32-byte seed.

    `digests` is an ordered sequence of (source_id, 32-byte digest). Order is
    part of the definition and comes from the record, so recomputation is
    unambiguous.

    Concatenate-and-hash, never average and never choose. The property that
    matters: the result is at least as unpredictable as the single best
    contributor, so adding a weak source can never weaken the seed. That is
    what lets us mix os.urandom in unconditionally as a floor while still
    making an honest claim about the physical sources above it.

    The source_id is bound in alongside its digest so that the same bytes
    arriving from a different source produce a different seed — otherwise a
    record could be relabelled after the fact without detection.
    """
    ikm = bytearray()
    for source_id, digest in digests:
        if len(digest) != HASH_LEN:
            raise ValueError(f"digest for {source_id} must be {HASH_LEN} bytes")
        sid = source_id.encode("utf-8")
        # length-prefixed so ("ab","c") cannot collide with ("a","bc")
        ikm.extend(len(sid).to_bytes(2, "big"))
        ikm.extend(sid)
        ikm.extend(digest)
    return hkdf(bytes(ikm), COMBINE_SALT, COMBINE_INFO, HASH_LEN)


def derive(seed: bytes, label: str, length: int = 32) -> bytes:
    """Derive an independent byte stream from a seed under a label.

    Two different labels give streams that cannot be distinguished from
    independent. This is why one mint serves a whole body of work: every
    render, palette, voice and layer takes its own label off the same seed and
    none of them correlate.

    Lengths over 8160 bytes (255*32) are served by re-keying with a chunk
    index rather than by extending the RFC 5869 counter, since that counter is
    a single byte. Streams under 8160 bytes are therefore exactly RFC 5869
    expand and check against the published vectors.
    """
    if len(seed) != HASH_LEN:
        raise ValueError(f"seed must be {HASH_LEN} bytes, got {len(seed)}")
    if length < 0:
        raise ValueError("length must be non-negative")

    info = DERIVE_INFO_PREFIX + b"/" + label.encode("utf-8")
    max_per_chunk = 255 * HASH_LEN
    if length <= max_per_chunk:
        return hkdf_expand(seed, info, length)

    # Chunk 0 uses the PLAIN info, so that a long draw is still a strict
    # extension of a short one. (An earlier version keyed chunk 0 as
    # ".../chunk/0", which silently broke the prefix property exactly at the
    # 8160-byte boundary — caught by test_chunking_boundary_is_continuous.)
    out = bytearray(hkdf_expand(seed, info, max_per_chunk))
    chunk = 1
    while len(out) < length:
        chunk_info = info + b"/chunk/" + str(chunk).encode("ascii")
        out.extend(hkdf_expand(seed, chunk_info,
                               min(max_per_chunk, length - len(out))))
        chunk += 1
    return bytes(out[:length])


# --- consumer-facing shapes -------------------------------------------------
# A composer wants a float or an int, not a bytestring. These are part of the
# portable spec too: a JS port must produce the same numbers, so the mapping
# from bytes to values is pinned here rather than left to each caller.


def derive_floats(seed: bytes, label: str, count: int):
    """`count` floats in [0, 1).

    Each float takes 8 bytes, uses the top 53 bits (the exactly-representable
    range of an IEEE-754 double) and divides by 2**53. Top-53-of-64 rather
    than 32 bits because 32-bit floats visibly quantise when you use them for
    slow parameter drift; and 53 rather than 64 because anything below the
    double's precision is decoration that JS could not reproduce anyway.
    """
    raw = derive(seed, label, count * 8)
    out = []
    for i in range(count):
        word = int.from_bytes(raw[i * 8:(i + 1) * 8], "big")
        out.append((word >> 11) / float(1 << 53))
    return out


def derive_ints(seed: bytes, label: str, count: int, low: int, high: int):
    """`count` ints uniform in [low, high] inclusive.

    Rejection sampling, not modulo. Modulo would bias toward the low end of
    the range, which in musical terms means a scale degree that shows up more
    often than the others for no reason anybody could hear a justification
    for. The rejection loop draws more bytes under the same label rather than
    re-keying, so the stream stays deterministic.
    """
    if high < low:
        raise ValueError("high must be >= low")
    span = high - low + 1
    if span == 1:
        return [low] * count

    nbytes = max(1, ((span - 1).bit_length() + 7) // 8)
    limit = 256 ** nbytes
    # largest multiple of span that fits; draws at or above this are rejected
    ceiling = limit - (limit % span)

    out = []
    pos = 0
    batch = max(count * nbytes * 2, 64)
    raw = derive(seed, label, batch)
    while len(out) < count:
        if pos + nbytes > len(raw):
            batch *= 2
            raw = derive(seed, label, batch)
            # re-walk from the start; the stream is deterministic so the
            # already-accepted prefix is identical
            pos = 0
            out = []
            continue
        word = int.from_bytes(raw[pos:pos + nbytes], "big")
        pos += nbytes
        if word < ceiling:
            out.append(low + (word % span))
    return out


def derive_choice(seed: bytes, label: str, items):
    """Pick one item. Convenience over derive_ints."""
    items = list(items)
    if not items:
        raise ValueError("cannot choose from an empty sequence")
    return items[derive_ints(seed, label, 1, 0, len(items) - 1)[0]]


def derive_shuffle(seed: bytes, label: str, items):
    """Deterministic Fisher-Yates. Returns a new list."""
    out = list(items)
    n = len(out)
    if n < 2:
        return out
    # one int per position, each under its own sub-label so that shuffling a
    # longer list does not change the earlier swaps
    for i in range(n - 1, 0, -1):
        j = derive_ints(seed, f"{label}/swap/{i}", 1, 0, i)[0]
        out[i], out[j] = out[j], out[i]
    return out
