"""Analysis configuration and resource limits.

Every limit here exists to bound the blast radius of a hostile capture file.
The defaults are sized for a laptop running the demo; they are all
overridable from the CLI and from environment variables prefixed
``SECUREMAILSCOPE_`` (see ``.env.example``).

Rationale for each default is in ``docs/threat-model.md``.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, fields
from typing import Final

from .errors import ConfigurationError

__all__ = ["AnalysisConfig", "ENV_PREFIX"]

ENV_PREFIX: Final = "SECUREMAILSCOPE_"

_MIB: Final = 1024 * 1024


@dataclass(frozen=True, slots=True)
class AnalysisConfig:
    """Bounds applied while reading and reassembling a capture.

    All values are hard ceilings: reaching one produces a diagnostic and marks
    the affected object truncated.  Nothing is ever silently discarded.
    """

    #: Largest capture file accepted at all. Checked before a single byte is parsed.
    max_capture_bytes: int = 512 * _MIB
    #: Maximum packet records read from one capture.
    max_packets: int = 2_000_000
    #: Largest single captured packet accepted. Guards absurd `incl_len` values.
    max_packet_bytes: int = 262_144
    #: Total application payload bytes retained across all sessions.
    max_total_payload_bytes: int = 256 * _MIB
    #: Application payload bytes retained per session (both directions summed).
    max_session_payload_bytes: int = 16 * _MIB
    #: Sessions held open simultaneously; beyond this new connections are refused.
    max_concurrent_sessions: int = 10_000
    #: Sessions recorded in total for one capture.
    max_total_sessions: int = 100_000
    #: Stored segment records per direction. Bounds provenance memory on
    #: pathological captures made of one-byte segments.
    max_segments_per_direction: int = 200_000
    #: Gap records kept per direction before we stop recording individual gaps.
    max_gaps_per_direction: int = 10_000
    #: Warnings emitted per distinct code before further ones are summarised.
    max_warnings_per_code: int = 100

    #: When true the report may carry a short hex preview of payload bytes.
    #: Off by default: reports must be safe to share.
    include_payload_preview: bool = False
    #: Length of that preview, in bytes, when explicitly enabled.
    payload_preview_bytes: int = 0

    def __post_init__(self) -> None:
        numeric = [
            "max_capture_bytes",
            "max_packets",
            "max_packet_bytes",
            "max_total_payload_bytes",
            "max_session_payload_bytes",
            "max_concurrent_sessions",
            "max_total_sessions",
            "max_segments_per_direction",
            "max_gaps_per_direction",
            "max_warnings_per_code",
        ]
        for name in numeric:
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise ConfigurationError(f"{name} must be a positive integer, got {value!r}")
        if self.payload_preview_bytes < 0:
            raise ConfigurationError("payload_preview_bytes must be >= 0")
        if self.include_payload_preview and self.payload_preview_bytes == 0:
            raise ConfigurationError(
                "include_payload_preview requires payload_preview_bytes > 0"
            )

    @classmethod
    def from_env(cls, environ: dict[str, str] | None = None) -> AnalysisConfig:
        """Build a config from ``SECUREMAILSCOPE_*`` environment variables.

        Unset variables keep their default.  An unparsable value is an error
        rather than a silent fallback, so a typo in a deployment cannot
        quietly disable a limit.
        """
        env = os.environ if environ is None else environ
        kwargs: dict[str, object] = {}
        for f in fields(cls):
            raw = env.get(ENV_PREFIX + f.name.upper())
            if raw is None:
                continue
            if f.type == "bool":
                lowered = raw.strip().lower()
                if lowered not in {"0", "1", "true", "false", "yes", "no"}:
                    raise ConfigurationError(
                        f"{ENV_PREFIX}{f.name.upper()} must be a boolean, got {raw!r}"
                    )
                kwargs[f.name] = lowered in {"1", "true", "yes"}
            else:
                try:
                    kwargs[f.name] = int(raw)
                except ValueError as exc:
                    raise ConfigurationError(
                        f"{ENV_PREFIX}{f.name.upper()} must be an integer, got {raw!r}"
                    ) from exc
        return cls(**kwargs)  # type: ignore[arg-type]
