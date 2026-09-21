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

    # --- application protocol layer (M2) ------------------------------------
    #: Longest protocol line accepted before the reader gives up on it and
    #: resynchronises at the next terminator. RFC 5321 caps an SMTP command at
    #: 512 octets and a reply line at 512; IMAP lines are longer in practice,
    #: so this is generous while still bounding a line with no terminator.
    max_line_bytes: int = 8192
    #: Largest IMAP literal skipped rather than parsed. Beyond this the parser
    #: cannot safely tell where the command resumes, so it stops.
    max_literal_bytes: int = 1_048_576
    #: Largest SMTP DATA body or POP3 multiline response skipped while looking
    #: for its terminator.
    max_message_body_bytes: int = 4_194_304
    #: Protocol events recorded per session before the rest are summarised.
    max_protocol_events_per_session: int = 2_000
    #: TLS records probed at a transition boundary. Framing evidence only.
    max_tls_records_probed: int = 8

    # --- TLS and certificate layer (M3) -------------------------------------
    #: Records framed per direction before parsing stops.
    max_tls_records_per_direction: int = 4096
    #: Largest single TLS record accepted. RFC 8446 caps TLSCiphertext at
    #: 2**14 + 256; the extra allowance tolerates non-conforming senders
    #: without permitting an unbounded allocation.
    max_tls_record_bytes: int = 16384 + 2048
    #: Plaintext handshake bytes buffered per direction for message reassembly.
    max_tls_handshake_bytes: int = 262_144
    #: Handshake messages parsed per direction.
    max_tls_handshake_messages: int = 256
    #: Certificates decoded from one Certificate message.
    max_certificates_per_chain: int = 16
    #: Largest single DER certificate decoded.
    max_certificate_bytes: int = 65_536

    #: PEM file holding the trust anchors used for chain verification. When
    #: unset, chain verification is reported NOT_AVAILABLE rather than
    #: silently falling back to a system store whose contents we cannot name.
    trust_store_path: str | None = None
    #: The server identity the analyst expects this session to have presented.
    #: Hostname verification is NOT_AVAILABLE without one; the destination IP
    #: is never used as a substitute.
    expected_server_identity: str | None = None
    #: Opt-in: treat the SNI observed in the ClientHello as the reference
    #: identity. Off by default -- SNI is what the client asked for, which is
    #: evidence, not an authorised expectation.
    trust_observed_sni_as_identity: bool = False
    #: Also report validity against the clock at analysis time, alongside the
    #: capture-time assessment.
    assess_certificates_at_current_time: bool = False
    #: Include base64 DER of each certificate in the report. Off by default.
    include_certificate_der: bool = False

    # --- security assessment (M4) -------------------------------------------
    #: Run the assessment layer. On by default: the forensic observations are
    #: reported unchanged either way, so this only adds the judgement block.
    assess_security: bool = True
    #: Judge certificate validity against the analysis clock instead of the
    #: capture timestamp. Off by default -- the capture's own clock is the only
    #: one that describes what was true when the traffic happened.
    assess_at_current_time: bool = False
    #: Comma-separated rule ids to disable, e.g. "TLS-PROTO-002,MAIL-004".
    disabled_rules: str | None = None
    #: Minimum weighted coverage before a numeric score is reported at all.
    #: Below it the engine reports SCORE_UNAVAILABLE. Expressed in percent so
    #: it can travel through an integer environment variable.
    minimum_score_coverage_percent: int = 50

    # --- forensic intelligence, batch mode (M5) -----------------------------
    #: Captures accepted in one investigation. Exceeding it produces an
    #: explicit warning; the surplus is never silently dropped, because a
    #: reader would take the result as covering everything they submitted.
    max_batch_captures: int = 64
    #: Sessions considered across the whole batch. Correlation and drift index
    #: on shared values rather than comparing all pairs, so this bounds memory
    #: rather than guarding against quadratic time.
    max_batch_sessions: int = 50_000
    #: Fingerprints retained. One per session, so this is effectively a cap on
    #: the size of the fingerprint block in the output.
    max_batch_fingerprints: int = 50_000
    #: Correlations reported. Truncation is warned about explicitly.
    max_batch_correlations: int = 5_000
    #: Timeline events reported. Truncation is warned about explicitly.
    max_timeline_events: int = 100_000
    #: Re-analyse a capture whose content hash was already seen. Off by
    #: default: two names for one file are not two pieces of evidence.
    allow_duplicate_captures: bool = False

    # --- machine learning (M6) ----------------------------------------------
    #: Run the ML layer. On by default when a model is installed; the layer
    #: reports its own status and never fails the analysis.
    enable_ml: bool = True
    #: Directory to load model artifacts from. None means the package default,
    #: which is the only location models are ever read from.
    model_directory: str | None = None

    #: When true the report may carry a short hex preview of payload bytes.
    #: Off by default: reports must be safe to share.
    include_payload_preview: bool = False
    #: Length of that preview, in bytes, when explicitly enabled.
    payload_preview_bytes: int = 0

    def __post_init__(self) -> None:
        numeric = [
            "max_tls_records_per_direction",
            "max_tls_record_bytes",
            "max_tls_handshake_bytes",
            "max_tls_handshake_messages",
            "max_certificates_per_chain",
            "max_certificate_bytes",
            "minimum_score_coverage_percent",
            "max_line_bytes",
            "max_literal_bytes",
            "max_message_body_bytes",
            "max_protocol_events_per_session",
            "max_tls_records_probed",
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
            "max_batch_captures",
            "max_batch_sessions",
            "max_batch_fingerprints",
            "max_batch_correlations",
            "max_timeline_events",
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
            if f.type == "str | None":
                kwargs[f.name] = raw
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
