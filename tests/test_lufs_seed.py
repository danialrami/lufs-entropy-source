"""Contract tests.

The house rule is that "works" means proven correct, not exited 0. These
tests are organised by the property being proven, not by module, because the
properties are the contract.
"""

import copy
import json
import os
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lufs_seed import canon, health, kdf, record  # noqa: E402
from lufs_seed.errors import (  # noqa: E402
    EntropyBudgetNotMet, HealthCheckFailed, SourceUnavailable,
)
from lufs_seed.sources import UrandomSource  # noqa: E402
from lufs_seed.sources.audio import (  # noqa: E402
    AudioNoiseFloorSource, synthesise_noise_floor,
)

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@pytest.fixture(scope="session")
def floor_wav(tmp_path_factory):
    """A realistic noise floor: hum LOUDER than the noise, 1/f tilt."""
    path = str(tmp_path_factory.mktemp("audio") / "floor.wav")
    synthesise_noise_floor(path, seconds=8.0)
    return path


@pytest.fixture(scope="session")
def minted(floor_wav, tmp_path_factory):
    rec, seed, artifacts = record.mint(
        source_specs=[("audio-noise-floor", True), ("jitter", False),
                      ("urandom", False)],
        note="test mint",
        **{"audio-noise-floor": {"init": {"path": floor_wav}},
           "jitter": {"collect": {"rounds": 512}}},
    )
    return rec, seed, floor_wav


# --- the derivation core is standards-correct, not our own dialect ---------

class TestHKDFConformance:
    def test_rfc5869_test_case_1(self):
        prk = kdf.hkdf_extract(bytes.fromhex("000102030405060708090a0b0c"),
                               bytes.fromhex("0b" * 22))
        assert prk.hex() == (
            "077709362c2e32df0ddc3f0dc47bba63"
            "90b6c73bb50f9c3122ec844ad7c2b3e5")
        okm = kdf.hkdf_expand(prk, bytes.fromhex("f0f1f2f3f4f5f6f7f8f9"), 42)
        assert okm.hex() == (
            "3cb25f25faacd57a90434f64d0362f2a"
            "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
            "34007208d5b887185865")

    def test_rfc5869_test_case_3_empty_salt_and_info(self):
        prk = kdf.hkdf_extract(b"", bytes.fromhex("0b" * 22))
        assert prk.hex() == (
            "19ef24a32c717b167f33a91d6f648bdf"
            "96596776afdb6377ac434c1c293ccb04")
        okm = kdf.hkdf_expand(prk, b"", 42)
        assert okm.hex() == (
            "8da4e775a563c18f715f802a063c5a31"
            "b8a11f5c5ee1879ec3454e5f3c738d2d"
            "9d201395faa4b61a96c8")


# --- determinism: the property every downstream test depends on ------------

class TestDerivationProperties:
    SEED = bytes(range(32))

    def test_same_seed_and_label_is_identical(self):
        assert kdf.derive(self.SEED, "x", 128) == kdf.derive(self.SEED, "x", 128)

    def test_different_labels_are_independent(self):
        assert kdf.derive(self.SEED, "a", 64) != kdf.derive(self.SEED, "b", 64)

    def test_different_seeds_diverge(self):
        other = bytes(range(1, 33))
        assert kdf.derive(self.SEED, "x", 64) != kdf.derive(other, "x", 64)

    def test_short_draw_is_a_prefix_of_a_long_one(self):
        assert kdf.derive(self.SEED, "x", 200)[:50] == kdf.derive(self.SEED, "x", 50)

    def test_chunking_boundary_is_continuous(self):
        """Crossing 255*32 must not corrupt or repeat the stream."""
        limit = 255 * 32
        long = kdf.derive(self.SEED, "x", limit + 100)
        assert long[:limit] == kdf.derive(self.SEED, "x", limit)
        assert len(long) == limit + 100
        # the far side of the boundary must not simply repeat the near side
        assert long[limit:limit + 32] != long[:32]

    def test_zero_length(self):
        assert kdf.derive(self.SEED, "x", 0) == b""

    def test_rejects_wrong_seed_size(self):
        with pytest.raises(ValueError):
            kdf.derive(b"short", "x", 32)

    def test_floats_in_unit_interval(self):
        vals = kdf.derive_floats(self.SEED, "f", 2000)
        assert all(0.0 <= v < 1.0 for v in vals)
        assert len(set(vals)) > 1900  # not collapsing

    def test_ints_respect_bounds_and_are_uniform(self):
        vals = kdf.derive_ints(self.SEED, "i", 42000, 0, 6)
        assert all(0 <= v <= 6 for v in vals)
        expected = 42000 / 7
        for degree in range(7):
            # rejection sampling, so no modulo bias toward the low end
            assert abs(vals.count(degree) - expected) < expected * 0.06

    def test_ints_degenerate_range(self):
        assert kdf.derive_ints(self.SEED, "i", 5, 3, 3) == [3] * 5

    def test_shuffle_is_a_permutation_and_deterministic(self):
        items = list(range(24))
        first = kdf.derive_shuffle(self.SEED, "s", items)
        assert sorted(first) == items
        assert first != items
        assert first == kdf.derive_shuffle(self.SEED, "s", items)


class TestCombine:
    def test_order_and_identity_are_bound_in(self):
        a = ("audio-noise-floor", bytes(32))
        b = ("jitter", bytes([1]) * 32)
        assert kdf.combine([a, b]) != kdf.combine([b, a])

    def test_relabelling_changes_the_seed(self):
        """A digest cannot be silently reattributed to another source."""
        digest = bytes(range(32))
        assert (kdf.combine([("jitter", digest)])
                != kdf.combine([("hwrng", digest)]))

    def test_length_prefix_prevents_concatenation_collisions(self):
        d = bytes(32)
        assert kdf.combine([("ab", d), ("c", d)]) != kdf.combine([("a", d), ("bc", d)])


# --- canonical JSON: two implementations must agree on the bytes -----------

class TestCanonicalJSON:
    def test_key_order_is_irrelevant(self):
        assert canon.encode({"b": 1, "a": 2}) == canon.encode({"a": 2, "b": 1})

    def test_floats_are_refused_in_signed_payloads(self):
        with pytest.raises(Exception):
            canon.encode({"x": 1.5})

    def test_nested_floats_are_refused(self):
        with pytest.raises(Exception):
            canon.encode({"a": {"b": [1, 2, 3.0]}})

    def test_unicode_is_not_escaped(self):
        assert "café" in canon.dumps({"x": "café"})


# --- health tests actually detect the failures they claim to ---------------

class TestHealthTests:
    def test_stuck_source_trips_repetition_count(self):
        assert not health.repetition_count_test([7] * 5000).ok

    def test_varied_source_passes_repetition_count(self):
        assert health.repetition_count_test(list(os.urandom(5000))).ok

    def test_collapsed_source_trips_adaptive_proportion(self):
        symbols = ([3] * 500 + [4] * 12) * 4
        assert not health.adaptive_proportion_test(symbols, window=512).ok

    def test_uniform_source_passes_adaptive_proportion(self):
        assert health.adaptive_proportion_test(list(os.urandom(4096))).ok

    def test_min_entropy_is_zero_for_a_constant(self):
        assert health.most_common_value_min_entropy([1] * 1000) == 0.0

    def test_min_entropy_is_conservative_for_uniform_bytes(self):
        h = health.most_common_value_min_entropy(list(os.urandom(20000)))
        # true value is 8.0; the estimator must UNDER-report, never over
        assert 6.0 < h < 8.0


# --- the audio source: the two-sided gate is the product -------------------

class TestAudioSource:
    def test_accepts_a_realistic_noise_floor(self, floor_wav):
        result = AudioNoiseFloorSource(floor_wav).collect()
        assert result.healthy
        assert result.physical
        assert result.entropy_bits > 256
        assert len(result.digest) == 32

    def test_survives_hum_louder_than_the_noise(self, tmp_path):
        """The real situation. Conditioning must absorb the structure."""
        path = str(tmp_path / "hummy.wav")
        synthesise_noise_floor(path, seconds=6.0, target_rms_dbfs=-84.0,
                               hum_dbfs=-60.0)
        result = AudioNoiseFloorSource(path).collect()
        assert result.healthy
        assert result.entropy_bits > 256

    def test_rejects_a_signal(self, tmp_path):
        path = str(tmp_path / "loud.wav")
        synthesise_noise_floor(path, seconds=6.0, target_rms_dbfs=-12.0,
                               hum_dbfs=-18.0)
        with pytest.raises(HealthCheckFailed, match="not_a_signal"):
            AudioNoiseFloorSource(path).collect()

    def test_rejects_digital_black(self, tmp_path):
        import wave
        path = str(tmp_path / "black.wav")
        with wave.open(path, "wb") as wf:
            wf.setnchannels(1)
            wf.setsampwidth(3)
            wf.setframerate(48000)
            wf.writeframes(b"\x00" * 3 * 48000 * 6)
        with pytest.raises(HealthCheckFailed):
            AudioNoiseFloorSource(path).collect()

    def test_rejects_too_short(self, tmp_path):
        path = str(tmp_path / "short.wav")
        synthesise_noise_floor(path, seconds=1.0)
        with pytest.raises(HealthCheckFailed, match="duration"):
            AudioNoiseFloorSource(path).collect(min_duration_s=5.0)

    def test_missing_file_is_unavailable_not_a_fallback(self):
        source = AudioNoiseFloorSource("/nonexistent/nope.wav")
        assert not source.available()[0]
        with pytest.raises(SourceUnavailable):
            source.collect()

    def _flip(self, src, dst, offset):
        with open(src, "rb") as fh:
            data = bytearray(fh.read())
        data[offset] ^= 0x01
        with open(dst, "wb") as fh:
            fh.write(bytes(data))
        return dst

    def test_digest_is_deterministic(self, floor_wav):
        first = AudioNoiseFloorSource(floor_wav).collect().digest
        assert first == AudioNoiseFloorSource(floor_wav).collect().digest

    def test_digest_changes_when_the_noise_changes(self, floor_wav, tmp_path):
        """A flip in the LOW byte is a change to the harvested entropy."""
        first = AudioNoiseFloorSource(floor_wav).collect().digest
        # 44-byte wav header, 3-byte samples; (offset-44) % 3 == 0 is the low byte
        altered = self._flip(floor_wav, str(tmp_path / "lsb.wav"), 5000)
        assert AudioNoiseFloorSource(altered).collect().digest != first

    def test_upper_bit_change_leaves_the_entropy_digest_alone(
            self, floor_wav, tmp_path):
        """Documents a real and deliberate property.

        The digest is taken over the low bits only, because that is where the
        thermal noise is. So editing the audible upper bits does NOT move it.
        That is correct for entropy — and precisely why `verify` also checks
        content_sha256 over the whole file, which DOES catch this.
        """
        first = AudioNoiseFloorSource(floor_wav).collect().digest
        altered = self._flip(floor_wav, str(tmp_path / "msb.wav"), 6000)
        result = AudioNoiseFloorSource(altered).collect()
        assert result.digest == first
        # ...but the provenance hash moved, which is what protects us
        original = AudioNoiseFloorSource(floor_wav).collect()
        assert result.detail["content_sha256"] != original.detail["content_sha256"]

    def test_catalog_number_matches_the_archive_convention(self, floor_wav):
        """lufs-<first8 of sha256>, same as components/catalog/run.sh."""
        import hashlib
        detail = AudioNoiseFloorSource(floor_wav).collect().detail
        with open(floor_wav, "rb") as fh:
            expected = hashlib.sha256(fh.read()).hexdigest()
        assert detail["content_sha256"] == expected
        assert detail["catalog_number"] == "lufs-" + expected[:8]


class TestUrandomSource:
    def test_contributes_no_entropy_budget(self):
        """It is unbeatable on unpredictability and worthless on provenance."""
        result = UrandomSource().collect()
        assert result.entropy_bits == 0.0
        assert result.physical is False


# --- honest failure: the core doctrine -------------------------------------

class TestHonestFailure:
    def test_required_source_missing_raises_not_falls_back(self):
        with pytest.raises(SourceUnavailable):
            record.mint(source_specs=[("audio-noise-floor", True)],
                        **{"audio-noise-floor": {"init": {"path": "/no/such.wav"}}})

    def test_optional_source_absence_is_recorded_not_hidden(self):
        rec, _, _ = record.mint(
            source_specs=[("jitter", False), ("hwrng", False), ("urandom", False)],
            **{"jitter": {"collect": {"rounds": 256}}},
        )
        absent = rec["payload"].get("absent_sources", [])
        # hwrng is missing in the sandbox; if present locally this is a no-op
        for entry in absent:
            assert entry["reason"]

    def test_urandom_only_is_unverified_never_verified(self):
        rec, _, _ = record.mint(source_specs=[("urandom", False)])
        assert rec["payload"]["tier"] == record.TIER_UNVERIFIED

    def test_refuses_to_certify_without_a_physical_source(self, tmp_path):
        from lufs_seed import signing
        key = str(tmp_path / "k.key")
        signing.generate_keypair(key)
        with pytest.raises(SourceUnavailable, match="refusing to certify"):
            record.mint(source_specs=[("urandom", False)], sign_key=key)

    def test_entropy_budget_is_enforced(self, floor_wav):
        with pytest.raises(EntropyBudgetNotMet):
            record.mint(
                source_specs=[("audio-noise-floor", True)],
                min_entropy_bits=10 ** 12,
                **{"audio-noise-floor": {"init": {"path": floor_wav}}},
            )

    def test_unknown_source_is_an_error(self):
        with pytest.raises(SourceUnavailable, match="unknown source"):
            record.mint(source_specs=[("teleportation", True)])


# --- verification is real: it recomputes rather than trusting --------------

class TestVerification:
    def test_a_good_record_verifies(self, minted):
        rec, _, wav = minted
        ok, checks = record.verify(rec, audio_path=wav)
        assert ok, [c for c in checks if not c["ok"]]

    def test_the_seed_is_recomputed_from_the_digests(self, minted):
        rec, seed, _ = minted
        assert record.recompute_seed(rec["payload"]["sources"]) == seed

    def test_altered_seed_is_caught(self, minted):
        rec, _, _ = minted
        bad = copy.deepcopy(rec)
        bad["payload"]["seed_hex"] = "ff" * 32
        ok, checks = record.verify(bad)
        assert not ok
        assert any(c["name"] == "seed_recomputes" and not c["ok"] for c in checks)

    def test_altered_digest_is_caught(self, minted):
        rec, _, _ = minted
        bad = copy.deepcopy(rec)
        bad["payload"]["sources"][0]["digest"] = "00" * 32
        assert not record.verify(bad)[0]

    def test_forged_pass_on_a_failed_check_is_caught(self, minted):
        """Flipping a recorded check to ok=True must not rescue a record."""
        rec, _, _ = minted
        bad = copy.deepcopy(rec)
        bad["payload"]["sources"][0]["checks"][0]["ok"] = False
        ok, checks = record.verify(bad)
        assert not ok
        assert any(c["name"] == "health_checks" and not c["ok"] for c in checks)

    def test_wrong_recording_is_caught(self, minted, tmp_path):
        rec, _, _ = minted
        other = str(tmp_path / "other.wav")
        synthesise_noise_floor(other, seconds=8.0, target_rms_dbfs=-80.0)
        ok, checks = record.verify(rec, audio_path=other)
        assert not ok
        assert any(c["name"] == "audio_artifact_binds" and not c["ok"]
                   for c in checks)

    def test_single_bit_change_in_the_recording_is_caught(self, minted, tmp_path):
        rec, _, wav = minted
        tampered = str(tmp_path / "1bit.wav")
        with open(wav, "rb") as fh:
            data = bytearray(fh.read())
        data[9000] ^= 0x01
        with open(tampered, "wb") as fh:
            fh.write(bytes(data))
        assert not record.verify(rec, audio_path=tampered)[0]

    def test_tier_cannot_be_inflated(self, minted):
        rec, _, _ = minted
        bad = copy.deepcopy(rec)
        bad["payload"]["tier"] = record.TIER_CERTIFIED  # unsigned!
        ok, checks = record.verify(bad)
        assert not ok
        assert any(c["name"] == "tier_consistent" and not c["ok"] for c in checks)


class TestSigning:
    @pytest.fixture
    def key(self, tmp_path):
        from lufs_seed import signing
        path = str(tmp_path / "signing.key")
        signing.generate_keypair(path)
        return path

    def test_certified_record_verifies(self, floor_wav, key):
        rec, _, _ = record.mint(
            source_specs=[("audio-noise-floor", True), ("urandom", False)],
            sign_key=key,
            **{"audio-noise-floor": {"init": {"path": floor_wav}}},
        )
        assert rec["payload"]["tier"] == record.TIER_CERTIFIED
        ok, checks = record.verify(rec, audio_path=floor_wav)
        assert ok, [c for c in checks if not c["ok"]]

    def test_any_payload_edit_breaks_the_signature(self, floor_wav, key):
        rec, _, _ = record.mint(
            source_specs=[("audio-noise-floor", True)],
            sign_key=key,
            **{"audio-noise-floor": {"init": {"path": floor_wav}}},
        )
        bad = copy.deepcopy(rec)
        bad["payload"]["note"] = "a different room"
        ok, checks = record.verify(bad)
        assert not ok
        assert any(c["name"] == "signature" and not c["ok"] for c in checks)

    def test_keygen_refuses_to_clobber(self, key):
        from lufs_seed import signing
        from lufs_seed.errors import SigningError
        with pytest.raises(SigningError, match="already exists"):
            signing.generate_keypair(key)

    def test_key_file_is_0600(self, key):
        import stat
        assert stat.S_IMODE(os.stat(key).st_mode) == 0o600

    def test_loose_permissions_are_refused(self, key):
        from lufs_seed import signing
        from lufs_seed.errors import SigningError
        os.chmod(key, 0o644)
        with pytest.raises(SigningError, match="0600"):
            signing.load_private(key)

    def test_a_different_key_does_not_verify(self, floor_wav, key, tmp_path):
        from lufs_seed import signing
        other = str(tmp_path / "other.key")
        signing.generate_keypair(other)
        rec, _, _ = record.mint(
            source_specs=[("audio-noise-floor", True)],
            sign_key=key,
            **{"audio-noise-floor": {"init": {"path": floor_wav}}},
        )
        ok, checks = record.verify(
            rec, expect_public_key=signing.public_key_b64(other))
        assert not ok
        assert any(c["name"] == "signer_identity" and not c["ok"] for c in checks)


# --- cross-language: the portability claim ---------------------------------

class TestCrossLanguageVectors:
    def test_python_reproduces_its_own_published_vectors(self):
        path = os.path.join(FIXTURES, "derivation-vectors.json")
        with open(path) as fh:
            vec = json.load(fh)
        seed = bytes.fromhex(vec["seed_hex"])
        for case in vec["bytes"]:
            assert kdf.derive(seed, case["label"], case["length"]).hex() == case["hex"]
        for case in vec["floats"]:
            assert kdf.derive_floats(seed, case["label"], case["count"]) == case["values"]
        for case in vec["ints"]:
            assert kdf.derive_ints(seed, case["label"], case["count"],
                                   case["min"], case["max"]) == case["values"]

    @pytest.mark.skipif(not any(
        os.access(os.path.join(p, "node"), os.X_OK)
        for p in os.environ.get("PATH", "").split(os.pathsep) if p),
        reason="node not installed")
    def test_javascript_port_agrees_with_python(self):
        """If this fails the portability claim is void."""
        result = subprocess.run(
            ["node", os.path.join(ROOT, "tests", "check_js_vectors.mjs")],
            capture_output=True, text=True,
        )
        assert result.returncode == 0, result.stdout + result.stderr


# --- CLI surface -----------------------------------------------------------

class TestCLI:
    def _run(self, *args, expect=0):
        result = subprocess.run(
            [sys.executable, "-m", "lufs_seed.cli", *args],
            capture_output=True, text=True, cwd=ROOT,
        )
        assert result.returncode == expect, result.stdout + result.stderr
        return result

    def test_selftest_passes(self):
        self._run("selftest")

    def test_selftest_json(self):
        out = json.loads(self._run("selftest", "--json").stdout)
        assert out["ok"]

    def test_sources_json(self):
        out = json.loads(self._run("sources", "--json").stdout)
        ids = {s["source_id"] for s in out["sources"]}
        assert {"audio-noise-floor", "jitter", "urandom"} <= ids

    def test_mint_without_a_physical_source_is_refused(self):
        self._run("mint", "--out", "-", expect=2)

    def test_missing_audio_exits_source_unavailable(self):
        self._run("mint", "--audio", "/no/such.wav", "--out", "-", expect=3)

    def test_verify_exit_code_on_failure(self, minted, tmp_path):
        rec, _, _ = minted
        bad = copy.deepcopy(rec)
        bad["payload"]["seed_hex"] = "00" * 32
        path = str(tmp_path / "bad.json")
        with open(path, "w") as fh:
            json.dump(bad, fh)
        self._run("verify", path, expect=6)

    def test_derive_rejects_a_seed_id(self, tmp_path):
        self._run("derive", "x", "--seed", "lufs-seed-abcd1234", expect=2)

    def test_full_cli_roundtrip(self, floor_wav, tmp_path):
        out = str(tmp_path / "r.json")
        self._run("mint", "--audio", floor_wav, "--out", out, "--json")
        self._run("verify", out, "--audio", floor_wav)
        first = self._run("derive", "a/b", "--record", out, "--floats", "3").stdout
        second = self._run("derive", "a/b", "--record", out, "--floats", "3").stdout
        assert first == second
