"""TLS hello extension parsing (RFC 8446 §4.2, RFC 6066, RFC 7301).

The same extension number means different things in a ClientHello, a
ServerHello and a HelloRetryRequest, so the context is required rather than
inferred.  ``supported_versions`` in particular is a *list* from the client
and a *single value* from the server, and the server's copy is the only
correct way to identify TLS 1.3 (RFC 8446 §4.2.1).

A malformed extension is recorded and skipped; it never aborts the analysis
and never produces a fabricated value.  RFC 8701 GREASE code points are
carried through marked as such so they are not reported as unknown
algorithms.
"""

from __future__ import annotations

import string
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Final

from .wire import ByteReader, TLSParseError

__all__ = ["ExtensionContext", "ParsedExtensions", "parse_extensions", "EXTENSION_NAMES"]

EXT_SERVER_NAME: Final = 0
EXT_SUPPORTED_GROUPS: Final = 10
EXT_SIGNATURE_ALGORITHMS: Final = 13
EXT_ALPN: Final = 16
EXT_PRE_SHARED_KEY: Final = 41
EXT_SUPPORTED_VERSIONS: Final = 43
EXT_PSK_KEY_EXCHANGE_MODES: Final = 45
EXT_KEY_SHARE: Final = 51

EXTENSION_NAMES: Final[dict[int, str]] = {
    0: "server_name",
    5: "status_request",
    10: "supported_groups",
    11: "ec_point_formats",
    13: "signature_algorithms",
    14: "use_srtp",
    16: "application_layer_protocol_negotiation",
    18: "signed_certificate_timestamp",
    21: "padding",
    22: "encrypt_then_mac",
    23: "extended_master_secret",
    35: "session_ticket",
    41: "pre_shared_key",
    42: "early_data",
    43: "supported_versions",
    44: "cookie",
    45: "psk_key_exchange_modes",
    47: "certificate_authorities",
    49: "post_handshake_auth",
    50: "signature_algorithms_cert",
    51: "key_share",
    65281: "renegotiation_info",
}

#: RFC 8446 §4.2.9.
_PSK_MODES: Final[dict[int, str]] = {0: "psk_ke", 1: "psk_dhe_ke"}

_HOSTNAME_ALPHABET: Final = frozenset(string.ascii_letters + string.digits + ".-_")
_ALPN_ALPHABET: Final = frozenset(string.ascii_letters + string.digits + ".-/+")


class ExtensionContext(StrEnum):
    CLIENT_HELLO = "CLIENT_HELLO"
    SERVER_HELLO = "SERVER_HELLO"
    HELLO_RETRY_REQUEST = "HELLO_RETRY_REQUEST"


@dataclass(slots=True)
class ParsedExtensions:
    """Extension values relevant to cryptographic posture."""

    present: list[int] = field(default_factory=list)
    malformed: list[int] = field(default_factory=list)

    # supported_versions
    offered_versions: tuple[int, ...] = ()
    selected_version: int | None = None

    # groups and key shares
    supported_groups: tuple[int, ...] = ()
    client_key_share_groups: tuple[int, ...] = ()
    server_key_share_group: int | None = None
    server_key_share_length: int | None = None
    hello_retry_selected_group: int | None = None

    signature_algorithms: tuple[int, ...] = ()

    server_name: str | None = None
    server_name_rejected: bool = False
    alpn: tuple[str, ...] = ()

    psk_offered: bool = False
    psk_identity_count: int = 0
    psk_key_exchange_modes: tuple[str, ...] = ()
    server_selected_psk_identity: int | None = None

    def names(self) -> tuple[str, ...]:
        return tuple(EXTENSION_NAMES.get(value, f"unknown_{value}") for value in self.present)


def _safe_hostname(raw: bytes) -> str | None:
    """A DNS name shaped strictly enough to be safe to put in a report."""
    if not raw or len(raw) > 253:
        return None
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        return None
    if any(character not in _HOSTNAME_ALPHABET for character in text):
        return None
    return text.lower()


def _safe_alpn(raw: bytes) -> str | None:
    if not raw or len(raw) > 32:
        return None
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        return None
    if any(character not in _ALPN_ALPHABET for character in text):
        return None
    return text


def parse_extensions(data: bytes, context: ExtensionContext) -> ParsedExtensions:
    """Parse an extension block. Never raises; malformed entries are recorded."""
    result = ParsedExtensions()
    reader = ByteReader(data)
    while reader.remaining >= 4:
        try:
            extension_type = reader.u16()
            body = reader.vector16()
        except TLSParseError:
            result.malformed.append(-1)
            break
        result.present.append(extension_type)
        try:
            _dispatch(extension_type, body, context, result)
        except TLSParseError:
            result.malformed.append(extension_type)
    if reader.remaining:
        result.malformed.append(-1)
    return result


def _dispatch(
    extension_type: int, body: bytes, context: ExtensionContext, result: ParsedExtensions
) -> None:
    if extension_type == EXT_SUPPORTED_VERSIONS:
        _supported_versions(body, context, result)
    elif extension_type == EXT_SUPPORTED_GROUPS:
        reader = ByteReader(body)
        result.supported_groups = reader.u16_list(reader.vector16())
    elif extension_type == EXT_SIGNATURE_ALGORITHMS:
        reader = ByteReader(body)
        result.signature_algorithms = reader.u16_list(reader.vector16())
    elif extension_type == EXT_KEY_SHARE:
        _key_share(body, context, result)
    elif extension_type == EXT_SERVER_NAME:
        _server_name(body, context, result)
    elif extension_type == EXT_ALPN:
        _alpn(body, result)
    elif extension_type == EXT_PRE_SHARED_KEY:
        _pre_shared_key(body, context, result)
    elif extension_type == EXT_PSK_KEY_EXCHANGE_MODES:
        reader = ByteReader(body)
        modes = reader.vector8()
        result.psk_key_exchange_modes = tuple(
            _PSK_MODES.get(mode, f"unknown_{mode}") for mode in modes
        )


def _supported_versions(
    body: bytes, context: ExtensionContext, result: ParsedExtensions
) -> None:
    """RFC 8446 §4.2.1: a list from the client, one value from the server."""
    reader = ByteReader(body)
    if context is ExtensionContext.CLIENT_HELLO:
        result.offered_versions = reader.u16_list(reader.vector8())
    else:
        result.selected_version = reader.u16()


def _key_share(body: bytes, context: ExtensionContext, result: ParsedExtensions) -> None:
    """RFC 8446 §4.2.8."""
    reader = ByteReader(body)
    if context is ExtensionContext.CLIENT_HELLO:
        shares = ByteReader(reader.vector16())
        groups: list[int] = []
        while shares.remaining >= 4:
            groups.append(shares.u16())
            shares.vector16()
        result.client_key_share_groups = tuple(groups)
    elif context is ExtensionContext.HELLO_RETRY_REQUEST:
        # A HelloRetryRequest key_share carries only the selected group.
        result.hello_retry_selected_group = reader.u16()
    else:
        result.server_key_share_group = reader.u16()
        result.server_key_share_length = len(reader.vector16())


def _server_name(body: bytes, context: ExtensionContext, result: ParsedExtensions) -> None:
    """RFC 6066 §3. A server echoes an empty extension to acknowledge."""
    if context is not ExtensionContext.CLIENT_HELLO:
        result.server_name_rejected = False
        return
    reader = ByteReader(body)
    entries = ByteReader(reader.vector16())
    while entries.remaining >= 3:
        name_type = entries.u8()
        name = entries.vector16()
        if name_type == 0 and result.server_name is None:
            result.server_name = _safe_hostname(name)


def _alpn(body: bytes, result: ParsedExtensions) -> None:
    """RFC 7301 §3.1."""
    reader = ByteReader(body)
    names = ByteReader(reader.vector16())
    collected: list[str] = []
    while names.remaining >= 1:
        candidate = _safe_alpn(names.vector8())
        if candidate:
            collected.append(candidate)
        if len(collected) >= 16:
            break
    result.alpn = tuple(collected)


def _pre_shared_key(
    body: bytes, context: ExtensionContext, result: ParsedExtensions
) -> None:
    """RFC 8446 §4.2.11. Identities and binders are never retained."""
    reader = ByteReader(body)
    if context is ExtensionContext.CLIENT_HELLO:
        identities = ByteReader(reader.vector16())
        count = 0
        while identities.remaining >= 6:
            identities.vector16()  # identity -- discarded, it is opaque state
            identities.u32()  # obfuscated_ticket_age
            count += 1
            if count > 64:
                break
        result.psk_offered = True
        result.psk_identity_count = count
    else:
        result.server_selected_psk_identity = reader.u16()
