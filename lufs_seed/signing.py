"""ed25519 signing — the certified tier.

Same primitive and the same intent as the Workchain certification tier: a
trusted author puts their name on an artifact. A seed record is signable
precisely because it is fully self-describing and float-free, so the bytes a
verifier reconstructs are the bytes that were signed.

Key handling rules, non-negotiable:
  * the private key never enters a record, a log line, or the JSON output
  * key files are written 0600 and refused if the mode is looser
  * signing is OPTIONAL; an unsigned seed is a legitimate `verified` seed, it
    just is not `certified`
"""

import base64
import os
import stat

from .errors import SigningError

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    from cryptography.exceptions import InvalidSignature
    HAVE_CRYPTO = True
except ImportError:  # pragma: no cover - environment dependent
    HAVE_CRYPTO = False

DEFAULT_KEY_DIR = os.path.expanduser("~/.config/lufs-seed")
DEFAULT_KEY_PATH = os.path.join(DEFAULT_KEY_DIR, "signing.key")
DEFAULT_PUB_PATH = os.path.join(DEFAULT_KEY_DIR, "signing.pub")


def _require_crypto():
    if not HAVE_CRYPTO:
        raise SigningError(
            "the `cryptography` package is required for signing/verification "
            "(pip install cryptography). Minting unsigned still works."
        )


def b64(raw):
    return base64.b64encode(raw).decode("ascii")


def unb64(text):
    return base64.b64decode(text.encode("ascii"))


def generate_keypair(key_path=DEFAULT_KEY_PATH, pub_path=None, force=False):
    """Create a signing keypair. Refuses to clobber without --force."""
    _require_crypto()
    pub_path = pub_path or (os.path.splitext(key_path)[0] + ".pub")

    if os.path.exists(key_path) and not force:
        raise SigningError(
            f"{key_path} already exists; refusing to overwrite. "
            "Use --force only if you are certain — signatures made with the "
            "old key become unverifiable."
        )

    directory = os.path.dirname(os.path.abspath(key_path))
    os.makedirs(directory, mode=0o700, exist_ok=True)

    private = Ed25519PrivateKey.generate()
    raw_priv = private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    raw_pub = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(b64(raw_priv) + "\n")
    os.chmod(key_path, 0o600)

    with open(pub_path, "w") as fh:
        fh.write(b64(raw_pub) + "\n")
    os.chmod(pub_path, 0o644)

    return {"key_path": key_path, "pub_path": pub_path, "public_key": b64(raw_pub)}


def load_private(key_path=DEFAULT_KEY_PATH):
    _require_crypto()
    if not os.path.isfile(key_path):
        raise SigningError(
            f"no signing key at {key_path}. Run `lufs-seed keygen` first, "
            "or mint without --sign."
        )
    mode = stat.S_IMODE(os.stat(key_path).st_mode)
    if mode & 0o077:
        raise SigningError(
            f"{key_path} has mode {oct(mode)}; private keys must be 0600. "
            f"Fix with: chmod 600 {key_path}"
        )
    with open(key_path) as fh:
        raw = unb64(fh.read().strip())
    if len(raw) != 32:
        raise SigningError(f"{key_path}: expected 32 raw key bytes, got {len(raw)}")
    return Ed25519PrivateKey.from_private_bytes(raw)


def public_key_b64(key_path=DEFAULT_KEY_PATH):
    private = load_private(key_path)
    return b64(private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ))


def sign(payload, key_path=DEFAULT_KEY_PATH):
    """Sign canonical bytes. Returns (signature_b64, public_key_b64)."""
    private = load_private(key_path)
    signature = private.sign(payload)
    pub = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return b64(signature), b64(pub)


def verify(payload, signature_b64, public_key_b64_str):
    """True if the signature is valid. Never raises on a bad signature."""
    _require_crypto()
    try:
        pub = Ed25519PublicKey.from_public_bytes(unb64(public_key_b64_str))
        pub.verify(unb64(signature_b64), payload)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False
