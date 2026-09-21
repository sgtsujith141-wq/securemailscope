"""Forward-secrecy observation with stated criteria.

M3 answers "what do the observed cryptographic parameters say about forward
secrecy?".  It does not answer "is this connection secure?" -- that is M4.

Two distinctions matter and are kept throughout:

**Capability versus observation.**  A negotiated ECDHE suite means the
protocol *will* use an ephemeral exchange. Seeing the ephemeral key material
on the wire -- a TLS 1.2 ServerKeyExchange or a TLS 1.3 server ``key_share``
-- is a stronger statement, and the two get different statuses.

**Negotiation versus completion.**  Passive analysis cannot verify a Finished
message without the traffic keys, so *no* session is reported as a
cryptographically completed handshake. ``handshake_completion_observable`` is
``False`` for every session M3 analyses, and the reason is carried with it.
"""

from __future__ import annotations

from ..models.evidence import PacketReference
from ..models.tls import ForwardSecrecyAssessment, ForwardSecrecyStatus, KeyExchangeAnalysis
from .registry import CipherSuiteInfo, KeyExchangeFamily

__all__ = ["assess_forward_secrecy", "COMPLETION_EXPLANATION"]

TLS13: int = 0x0304

COMPLETION_EXPLANATION = (
    "Handshake completion is not observable passively. Verifying a Finished message "
    "requires the handshake traffic keys, which a capture does not contain, so no "
    "session is reported as a cryptographically completed handshake. What is reported "
    "is what was negotiated and what key material was visible."
)

_BASE_LIMITATIONS: tuple[str, ...] = (
    "Forward secrecy here is a property of the negotiated key exchange, not a "
    "guarantee about the implementation's key handling or its reuse of ephemeral keys.",
    "This is an observation. Whether it constitutes a finding is an M4 question.",
)


def assess_forward_secrecy(
    *,
    key_exchange: KeyExchangeAnalysis,
    suite: CipherSuiteInfo | None,
    selected_version: int | None,
    server_hello_observed: bool,
    evidence_refs: tuple[PacketReference, ...],
) -> ForwardSecrecyAssessment:
    limitations = list(_BASE_LIMITATIONS)

    if not server_hello_observed or selected_version is None:
        return ForwardSecrecyAssessment(
            status=ForwardSecrecyStatus.UNKNOWN_INCOMPLETE_EVIDENCE,
            criteria=(
                "No ServerHello was observed, so nothing was negotiated. A client's "
                "offered cipher suites and key shares describe what it would have "
                "accepted, never what was used."
            ),
            ephemeral_key_exchange_negotiated=None,
            handshake_completion_explanation=COMPLETION_EXPLANATION,
            evidence_refs=evidence_refs,
            limitations=tuple(limitations),
        )

    if selected_version == TLS13:
        return _tls13(key_exchange, evidence_refs, limitations)
    return _tls12(key_exchange, suite, evidence_refs, limitations)


def _tls13(
    key_exchange: KeyExchangeAnalysis,
    evidence_refs: tuple[PacketReference, ...],
    limitations: list[str],
) -> ForwardSecrecyAssessment:
    share_observed = key_exchange.selected_group is not None

    if key_exchange.method == "PSK":
        return ForwardSecrecyAssessment(
            status=ForwardSecrecyStatus.PSK_ONLY,
            criteria=(
                "RFC 8446 §4.2.9: the server selected a pre-shared key and returned no "
                "key_share, so session keys derive from the PSK alone with no ephemeral "
                "contribution. Compromise of the PSK exposes this session."
            ),
            ephemeral_key_exchange_negotiated=False,
            ephemeral_key_material_observed=False,
            handshake_completion_explanation=COMPLETION_EXPLANATION,
            evidence_refs=evidence_refs,
            limitations=tuple(limitations),
        )

    if share_observed:
        combined = key_exchange.method == "PSK_EPHEMERAL"
        group = key_exchange.selected_group
        group_label = (group.name or group.hex_value) if group else "an unnamed group"
        return ForwardSecrecyAssessment(
            status=ForwardSecrecyStatus.EPHEMERAL_OBSERVED,
            criteria=(
                "RFC 8446 §4.2.8: the ServerHello carried a key_share entry for group "
                f"{group_label}"
                ", so an ephemeral (EC)DHE exchange contributed to the session keys and "
                "the server's ephemeral public key was observed on the wire."
                + (
                    " It was combined with a pre-shared key (psk_dhe_ke)."
                    if combined
                    else ""
                )
            ),
            ephemeral_key_exchange_negotiated=True,
            ephemeral_key_material_observed=True,
            handshake_completion_explanation=COMPLETION_EXPLANATION,
            evidence_refs=evidence_refs,
            limitations=tuple(limitations),
        )

    return ForwardSecrecyAssessment(
        status=ForwardSecrecyStatus.UNKNOWN_INCOMPLETE_EVIDENCE,
        criteria=(
            "TLS 1.3 was negotiated but the ServerHello carried neither a key_share nor "
            "a selected pre-shared key that this capture could read, so how the session "
            "keys were established is not established. TLS 1.3 is not assumed to be "
            "forward secret merely because it is TLS 1.3."
        ),
        ephemeral_key_exchange_negotiated=None,
        handshake_completion_explanation=COMPLETION_EXPLANATION,
        evidence_refs=evidence_refs,
        limitations=tuple(limitations),
    )


def _tls12(
    key_exchange: KeyExchangeAnalysis,
    suite: CipherSuiteInfo | None,
    evidence_refs: tuple[PacketReference, ...],
    limitations: list[str],
) -> ForwardSecrecyAssessment:
    if suite is None:
        return ForwardSecrecyAssessment(
            status=ForwardSecrecyStatus.UNKNOWN_INCOMPLETE_EVIDENCE,
            criteria=(
                "The selected cipher suite is not in this build's registry, so the key "
                "exchange family it encodes is unknown. Nothing is inferred from the "
                "numeric identifier."
            ),
            handshake_completion_explanation=COMPLETION_EXPLANATION,
            evidence_refs=evidence_refs,
            limitations=tuple(limitations),
        )

    family = suite.key_exchange
    if family is KeyExchangeFamily.RSA:
        return ForwardSecrecyAssessment(
            status=ForwardSecrecyStatus.STATIC_RSA_KEY_EXCHANGE,
            criteria=(
                f"RFC 5246 §7.4.7.1: the negotiated suite {suite.name} uses static RSA "
                "key exchange. The client encrypts the premaster secret to the server's "
                "long-term certificate key, so anyone who later obtains that key can "
                "decrypt this recorded session. No forward secrecy."
            ),
            ephemeral_key_exchange_negotiated=False,
            ephemeral_key_material_observed=False,
            handshake_completion_explanation=COMPLETION_EXPLANATION,
            evidence_refs=evidence_refs,
            limitations=tuple(limitations),
        )

    if family is KeyExchangeFamily.PSK:
        return ForwardSecrecyAssessment(
            status=ForwardSecrecyStatus.PSK_ONLY,
            criteria=(
                f"The negotiated suite {suite.name} uses a pre-shared key with no "
                "ephemeral Diffie-Hellman contribution, so it provides no forward secrecy."
            ),
            ephemeral_key_exchange_negotiated=False,
            handshake_completion_explanation=COMPLETION_EXPLANATION,
            evidence_refs=evidence_refs,
            limitations=tuple(limitations),
        )

    if family in (
        KeyExchangeFamily.DH_STATIC,
        KeyExchangeFamily.ECDH_STATIC,
    ):
        return ForwardSecrecyAssessment(
            status=ForwardSecrecyStatus.NOT_FORWARD_SECRET,
            criteria=(
                f"The negotiated suite {suite.name} uses a static Diffie-Hellman key "
                "from the server's certificate rather than an ephemeral one, so it "
                "provides no forward secrecy."
            ),
            ephemeral_key_exchange_negotiated=False,
            handshake_completion_explanation=COMPLETION_EXPLANATION,
            evidence_refs=evidence_refs,
            limitations=tuple(limitations),
        )

    if family in (KeyExchangeFamily.ECDHE, KeyExchangeFamily.DHE, KeyExchangeFamily.PSK_EPHEMERAL):
        if key_exchange.server_key_exchange_observed:
            group = key_exchange.selected_group
            if group is not None:
                detail = f"group {group.name or group.hex_value}"
            elif key_exchange.dh_prime_length_bits:
                detail = f"a {key_exchange.dh_prime_length_bits}-bit finite-field group"
            else:
                detail = "an ephemeral group"
            return ForwardSecrecyAssessment(
                status=ForwardSecrecyStatus.EPHEMERAL_OBSERVED,
                criteria=(
                    f"RFC 4492 §5.4 / RFC 5246 §7.4.3: suite {suite.name} negotiates an "
                    f"ephemeral exchange, and a plaintext ServerKeyExchange carrying "
                    f"{detail} was observed, so the ephemeral key material itself was on "
                    "the wire."
                ),
                ephemeral_key_exchange_negotiated=True,
                ephemeral_key_material_observed=True,
                handshake_completion_explanation=COMPLETION_EXPLANATION,
                evidence_refs=evidence_refs,
                limitations=tuple(limitations),
            )
        return ForwardSecrecyAssessment(
            status=ForwardSecrecyStatus.CAPABLE_NEGOTIATED,
            criteria=(
                f"The negotiated suite {suite.name} uses an ephemeral key exchange, so "
                "the protocol provides forward secrecy, but no plaintext "
                "ServerKeyExchange was captured, so the ephemeral key material itself "
                "was not observed."
            ),
            ephemeral_key_exchange_negotiated=True,
            ephemeral_key_material_observed=False,
            handshake_completion_explanation=COMPLETION_EXPLANATION,
            evidence_refs=evidence_refs,
            limitations=tuple(limitations),
        )

    if family is KeyExchangeFamily.ANON:
        return ForwardSecrecyAssessment(
            status=ForwardSecrecyStatus.NOT_FORWARD_SECRET,
            criteria=(
                f"The negotiated suite {suite.name} is anonymous: there is no server "
                "authentication, so forward secrecy is not a meaningful property here."
            ),
            ephemeral_key_exchange_negotiated=None,
            handshake_completion_explanation=COMPLETION_EXPLANATION,
            evidence_refs=evidence_refs,
            limitations=tuple(limitations),
        )

    return ForwardSecrecyAssessment(
        status=ForwardSecrecyStatus.UNKNOWN_INCOMPLETE_EVIDENCE,
        criteria=(
            f"The key exchange family of suite {suite.name} is not classified by this "
            "build, so no forward-secrecy conclusion is drawn."
        ),
        handshake_completion_explanation=COMPLETION_EXPLANATION,
        evidence_refs=evidence_refs,
        limitations=tuple(limitations),
    )
