"""Typed failures.

Honest failure is the point of this tool, so every refusal has a name and a
distinct exit code. Nothing here is ever swallowed into a fallback.
"""


class LufsSeedError(Exception):
    """Base class. `exit_code` is what the CLI returns."""

    exit_code = 1


class SourceUnavailable(LufsSeedError):
    """A requested entropy source is not present on this machine.

    Deliberately fatal. The old EntropyOrchestrator silently fell back to
    os.urandom in this case, which is exactly the lie this tool exists to
    stop telling.
    """

    exit_code = 3


class HealthCheckFailed(LufsSeedError):
    """A source produced bytes that did not pass its health gate."""

    exit_code = 4


class EntropyBudgetNotMet(LufsSeedError):
    """The assessed min-entropy across physical sources is below threshold."""

    exit_code = 5


class VerificationFailed(LufsSeedError):
    """A seed record failed to verify."""

    exit_code = 6


class SigningError(LufsSeedError):
    """Key material missing, malformed, or signature invalid."""

    exit_code = 7


class UsageError(LufsSeedError):
    """Bad invocation."""

    exit_code = 2
