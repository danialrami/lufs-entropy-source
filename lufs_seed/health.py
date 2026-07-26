"""Health tests — the part that makes a claim checkable.

Two families:

  * NIST SP 800-90B continuous tests (repetition count, adaptive proportion).
    These are the standard "the source just died" detectors. They catch a
    stuck converter or a wedged driver, which is the realistic failure, not a
    cryptographic attack.
  * A conservative min-entropy estimate (SP 800-90B section 6.3.1, the
    "most common value" estimator). Deliberately the *pessimistic* one: it
    looks only at the frequency of the single most common symbol and ignores
    every other structure, so it under-reports a good source and cannot be
    talked into over-reporting a bad one. For a gate, that asymmetry is the
    one you want.

None of these prove randomness. Nothing can. They prove *absence of the
obvious failures*, which is the honest claim, and it is the claim the record
makes.
"""

import math
from collections import Counter

from .canon import fmt_ratio


class CheckResult:
    """One named check. `gating` means a failure fails the mint."""

    def __init__(self, name, ok, detail, gating=True):
        self.name = name
        self.ok = bool(ok)
        self.detail = detail
        self.gating = bool(gating)

    def to_record(self):
        return {
            "name": self.name,
            "ok": self.ok,
            "gating": self.gating,
            "detail": self.detail,
        }

    def __repr__(self):
        return f"<CheckResult {self.name} ok={self.ok}>"


def repetition_count_test(symbols, alpha_exp=20, h_assumed=1.0):
    """SP 800-90B 4.4.1 — trips if one value repeats implausibly often.

    Cutoff C = 1 + ceil(alpha_exp / H). With the default H=1 bit/symbol this
    is a blunt instrument by design: it exists to catch a source that has
    flatlined, not to grade quality.
    """
    if not symbols:
        return CheckResult("repetition_count", False, "no symbols", True)

    cutoff = 1 + math.ceil(alpha_exp / max(h_assumed, 1e-9))
    longest = 1
    run = 1
    prev = symbols[0]
    for sym in symbols[1:]:
        run = run + 1 if sym == prev else 1
        if run > longest:
            longest = run
        prev = sym

    ok = longest < cutoff
    return CheckResult(
        "repetition_count",
        ok,
        f"longest run {longest}, cutoff {cutoff}"
        + ("" if ok else " — source may be stuck"),
        True,
    )


def adaptive_proportion_test(symbols, window=512, h_assumed=1.0):
    """SP 800-90B 4.4.2 — trips if one value dominates a sliding window.

    Catches partial failure: a source still changing, but collapsed onto a
    small set of values.
    """
    n = len(symbols)
    if n < window:
        return CheckResult(
            "adaptive_proportion",
            False,
            f"need >= {window} symbols, got {n}",
            True,
        )

    # Binomial cutoff at roughly alpha = 2^-20, normal approximation.
    p = 2.0 ** (-max(h_assumed, 1e-9))
    mean = window * p
    sd = math.sqrt(max(window * p * (1.0 - p), 1e-12))
    cutoff = min(window, int(math.ceil(mean + 4.75 * sd)))

    worst = 0
    # step the window rather than slide it by one; 90B permits
    # non-overlapping windows and it keeps this linear
    for start in range(0, n - window + 1, window):
        counts = Counter(symbols[start:start + window])
        worst = max(worst, counts.most_common(1)[0][1])

    ok = worst <= cutoff
    return CheckResult(
        "adaptive_proportion",
        ok,
        f"max symbol count {worst} in window {window}, cutoff {cutoff}"
        + ("" if ok else " — source collapsed onto few values"),
        True,
    )


def most_common_value_min_entropy(symbols):
    """SP 800-90B 6.3.1 — conservative min-entropy, bits per symbol.

    Uses the upper confidence bound on the most common value's probability,
    so the entropy estimate is a lower bound. Returns 0.0 for degenerate
    input rather than raising: a source with one symbol genuinely has no
    entropy, and saying so is more useful than an exception.
    """
    n = len(symbols)
    if n == 0:
        return 0.0
    counts = Counter(symbols)
    p_hat = counts.most_common(1)[0][1] / n
    # 99% upper bound
    p_u = min(1.0, p_hat + 2.576 * math.sqrt(max(p_hat * (1.0 - p_hat), 0.0) / n))
    if p_u <= 0.0:
        return 0.0
    return max(0.0, -math.log2(p_u))


def assess(symbols, label, window=512):
    """Run the standard battery over a symbol sequence.

    Returns (checks, min_entropy_per_symbol, total_bits).
    """
    checks = [
        repetition_count_test(symbols),
        adaptive_proportion_test(symbols, window=window),
    ]
    h = most_common_value_min_entropy(symbols)
    total = h * len(symbols)

    checks.append(
        CheckResult(
            "min_entropy_estimate",
            h > 0.0,
            f"{label}: {fmt_ratio(h)} bits/symbol over {len(symbols)} symbols "
            f"= {fmt_ratio(total)} bits (SP 800-90B 6.3.1, conservative)",
            True,
        )
    )
    return checks, h, total
