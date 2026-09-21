"""Observable key-exchange identification.

TLS 1.2 and TLS 1.3 answer "how were keys established?" from entirely
different evidence, and conflating them is the classic way to produce a wrong
report:

* **TLS 1.2** encodes the key exchange in the cipher suite name
  (``TLS_ECDHE_RSA_WITH_...``), and the ServerKeyExchange message carries the
  actual group and ephemeral public key (RFC 4492 §5.4).
* **TLS 1.3** cipher suites encode *only* an AEAD and a hash (RFC 8446 §B.4).
  Key establishment comes from the ``key_share`` and pre-shared-key
  extensions. Reading ECDHE out of ``TLS_AES_128_GCM_SHA256`` would be
  inventing it.

A client's offered groups are capability, not negotiation. Only the server's
selection establishes what was used.
"""

from __future__ import annotations

from ..models.evidence import EvidenceStatus, PacketReference
from ..models.tls import CodePointRef, KeyExchangeAnalysis
from .extensions import ParsedExtensions
from .handshake import ClientHelloInfo, ServerHelloInfo, ServerKeyExchangeInfo
from .registry import (
    CipherSuiteInfo,
    KeyExchangeFamily,
    is_grease,
    lookup_named_group,
    lookup_signature_scheme,
)

__all__ = ["code_point", "named_group_ref", "analyze_key_exchange"]

TLS13: int = 0x0304


def code_point(value: int, name: str | None) -> CodePointRef:
    return CodePointRef(
        value=value,
        hex_value=f"0x{value:04x}",
        name=name,
        known=name is not None,
        grease=is_grease(value),
    )


def named_group_ref(value: int) -> CodePointRef:
    info = lookup_named_group(value)
    return code_point(value, info.name if info else None)


def _signature_refs(values: tuple[int, ...]) -> tuple[CodePointRef, ...]:
    return tuple(code_point(value, lookup_signature_scheme(value)) for value in values[:64])


def analyze_key_exchange(
    *,
    client_hello: ClientHelloInfo | None,
    server_hello: ServerHelloInfo | None,
    server_key_exchange: ServerKeyExchangeInfo | None,
    selected_version: int | None,
    suite: CipherSuiteInfo | None,
    hello_retry_request: bool,
    evidence_refs: tuple[PacketReference, ...],
) -> KeyExchangeAnalysis:
    limitations: list[str] = []
    client_groups: tuple[CodePointRef, ...] = ()
    client_shares: tuple[CodePointRef, ...] = ()
    signature_algorithms: tuple[CodePointRef, ...] = ()
    psk_offered = False
    psk_modes: tuple[str, ...] = ()

    if client_hello is not None:
        extensions = client_hello.extensions
        client_groups = tuple(named_group_ref(v) for v in extensions.supported_groups[:64])
        client_shares = tuple(
            named_group_ref(v) for v in extensions.client_key_share_groups[:32]
        )
        signature_algorithms = _signature_refs(extensions.signature_algorithms)
        psk_offered = extensions.psk_offered
        psk_modes = extensions.psk_key_exchange_modes

    if server_hello is None:
        limitations.append(
            "No ServerHello was observed, so nothing was negotiated: the client's offered "
            "groups describe capability only."
        )
        return KeyExchangeAnalysis(
            method="UNKNOWN",
            method_status=EvidenceStatus.UNKNOWN,
            client_supported_groups=client_groups,
            client_key_share_groups=client_shares,
            client_signature_algorithms=signature_algorithms,
            psk_offered=psk_offered,
            psk_key_exchange_modes=psk_modes,
            hello_retry_request_observed=hello_retry_request,
            evidence_refs=evidence_refs,
            limitations=tuple(limitations),
        )

    server_extensions = server_hello.extensions
    selected_psk = server_extensions.server_selected_psk_identity is not None

    if selected_version == TLS13:
        return _tls13(
            server_extensions=server_extensions,
            selected_psk=selected_psk,
            psk_offered=psk_offered,
            psk_modes=psk_modes,
            client_groups=client_groups,
            client_shares=client_shares,
            signature_algorithms=signature_algorithms,
            hello_retry_request=hello_retry_request,
            evidence_refs=evidence_refs,
            limitations=limitations,
        )

    return _tls12(
        suite=suite,
        server_key_exchange=server_key_exchange,
        client_groups=client_groups,
        client_shares=client_shares,
        signature_algorithms=signature_algorithms,
        psk_offered=psk_offered,
        psk_modes=psk_modes,
        selected_psk=selected_psk,
        hello_retry_request=hello_retry_request,
        evidence_refs=evidence_refs,
        limitations=limitations,
    )


def _tls13(
    *,
    server_extensions: ParsedExtensions,
    selected_psk: bool,
    psk_offered: bool,
    psk_modes: tuple[str, ...],
    client_groups: tuple[CodePointRef, ...],
    client_shares: tuple[CodePointRef, ...],
    signature_algorithms: tuple[CodePointRef, ...],
    hello_retry_request: bool,
    evidence_refs: tuple[PacketReference, ...],
    limitations: list[str],
) -> KeyExchangeAnalysis:
    share_group = server_extensions.server_key_share_group
    selected_group = named_group_ref(share_group) if share_group is not None else None

    if share_group is not None and selected_psk:
        method, source = "PSK_EPHEMERAL", "PSK_EXTENSIONS"
        limitations.append(
            "The server selected a pre-shared key and also returned a key_share, so key "
            "establishment combines the PSK with an ephemeral exchange (RFC 8446 §2.2)."
        )
    elif share_group is not None:
        info = lookup_named_group(share_group)
        family = info.family if info else None
        method = "ECDHE" if family == "ECDHE" else "DHE" if family == "FFDHE" else "EPHEMERAL"
        source = "KEY_SHARE_EXTENSION"
    elif selected_psk:
        method, source = "PSK", "PSK_EXTENSIONS"
        limitations.append(
            "The server selected a pre-shared key and returned no key_share, so no "
            "ephemeral exchange contributed to the session keys (RFC 8446 §4.2.9)."
        )
    else:
        method, source = "UNKNOWN", None
        limitations.append(
            "The ServerHello carried neither a key_share nor a selected pre-shared key, "
            "so how keys were established cannot be determined."
        )

    limitations.append(
        "TLS 1.3 cipher suites encode only an AEAD and a hash (RFC 8446 §B.4); key "
        "exchange and authentication are never inferred from the suite name."
    )
    if hello_retry_request:
        limitations.append(
            "A HelloRetryRequest was observed: the server rejected the client's initial "
            "key share and asked for a different group (RFC 8446 §4.1.4)."
        )

    return KeyExchangeAnalysis(
        method=method,
        method_status=EvidenceStatus.OBSERVED
        if method != "UNKNOWN"
        else EvidenceStatus.UNKNOWN,
        method_source=source,
        client_supported_groups=client_groups,
        client_key_share_groups=client_shares,
        selected_group=selected_group,
        selected_group_source="SERVER_KEY_SHARE" if selected_group else None,
        server_key_share_length=server_extensions.server_key_share_length,
        psk_offered=psk_offered,
        psk_key_exchange_modes=psk_modes,
        server_selected_psk=selected_psk,
        hello_retry_request_observed=hello_retry_request,
        client_signature_algorithms=signature_algorithms,
        evidence_refs=evidence_refs,
        limitations=tuple(limitations),
    )


def _tls12(
    *,
    suite: CipherSuiteInfo | None,
    server_key_exchange: ServerKeyExchangeInfo | None,
    client_groups: tuple[CodePointRef, ...],
    client_shares: tuple[CodePointRef, ...],
    signature_algorithms: tuple[CodePointRef, ...],
    psk_offered: bool,
    psk_modes: tuple[str, ...],
    selected_psk: bool,
    hello_retry_request: bool,
    evidence_refs: tuple[PacketReference, ...],
    limitations: list[str],
) -> KeyExchangeAnalysis:
    if suite is None:
        limitations.append(
            "The selected cipher suite is not in this build's registry, so the key "
            "exchange family it encodes is not known. The numeric identifier is reported "
            "as observed."
        )
        return KeyExchangeAnalysis(
            method="UNKNOWN",
            method_status=EvidenceStatus.UNKNOWN,
            method_source="CIPHER_SUITE",
            client_supported_groups=client_groups,
            client_key_share_groups=client_shares,
            client_signature_algorithms=signature_algorithms,
            psk_offered=psk_offered,
            psk_key_exchange_modes=psk_modes,
            hello_retry_request_observed=hello_retry_request,
            evidence_refs=evidence_refs,
            limitations=tuple(limitations),
        )

    family = suite.key_exchange
    selected_group: CodePointRef | None = None
    group_source: str | None = None
    public_length: int | None = None
    prime_bits: int | None = None
    observed = server_key_exchange is not None and server_key_exchange.parsed

    if observed and server_key_exchange is not None:
        if server_key_exchange.named_curve is not None:
            selected_group = named_group_ref(server_key_exchange.named_curve)
            group_source = "SERVER_KEY_EXCHANGE"
        public_length = server_key_exchange.public_key_length
        prime_bits = server_key_exchange.dh_prime_length_bits
    elif family in (KeyExchangeFamily.ECDHE, KeyExchangeFamily.DHE):
        limitations.append(
            "The cipher suite names an ephemeral key exchange, but no plaintext "
            "ServerKeyExchange was observed, so the group actually used is not "
            "established. The client's offered groups are capability only."
        )

    if family is KeyExchangeFamily.RSA:
        limitations.append(
            "Static RSA key exchange: the premaster secret is encrypted to the server's "
            "long-term certificate key, so this session has no forward secrecy "
            "(RFC 5246 §7.4.7.1)."
        )

    return KeyExchangeAnalysis(
        method=family.value,
        method_status=EvidenceStatus.OBSERVED
        if family is not KeyExchangeFamily.UNKNOWN
        else EvidenceStatus.UNKNOWN,
        method_source="CIPHER_SUITE",
        client_supported_groups=client_groups,
        client_key_share_groups=client_shares,
        selected_group=selected_group,
        selected_group_source=group_source,
        server_key_exchange_observed=observed,
        server_key_exchange_curve=selected_group,
        server_key_exchange_public_length=public_length,
        dh_prime_length_bits=prime_bits,
        psk_offered=psk_offered,
        psk_key_exchange_modes=psk_modes,
        server_selected_psk=selected_psk if psk_offered else None,
        hello_retry_request_observed=hello_retry_request,
        client_signature_algorithms=signature_algorithms,
        evidence_refs=evidence_refs,
        limitations=tuple(limitations),
    )
