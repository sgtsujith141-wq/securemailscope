"""Per-session TLS analysis.

Orchestrates: locate where TLS begins, frame records, reassemble handshake
messages up to the encryption boundary, read the negotiated parameters, and
hand any plaintext certificates to the certificate layer.

The encryption boundary is the spine of this module.  Everything before it is
evidence; everything after it is bytes we can frame but must not interpret:

* **TLS 1.2** -- a ChangeCipherSpec ends plaintext for the direction that sent
  it (RFC 5246 §7.1).
* **TLS 1.3** -- everything after the ServerHello is encrypted under handshake
  traffic keys (RFC 8446 §2). The compatibility ChangeCipherSpec that
  middlebox-friendly implementations emit is *not* evidence of a TLS 1.2
  handshake, and ``application_data`` records carrying encrypted handshake
  messages are never parsed as plaintext.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from ..certificates.parse import CRYPTOGRAPHY_AVAILABLE, parse_certificate
from ..certificates.truststore import LoadedTrustStore
from ..certificates.validate import validate_chain
from ..config import AnalysisConfig
from ..diagnostics import WarningSink
from ..models.certificates import (
    CertificateInventory,
    CertificateObservation,
    CertificateVisibility,
)
from ..models.evidence import EvidenceStatus, PacketReference, Severity, WarningCode
from ..models.protocol import ProtocolSessionAnalysis, TLSContentType, UpgradeState
from ..models.tcp import Direction, TCPSession
from ..models.tls import (
    CipherSuiteAnalysis,
    CodePointRef,
    EncryptionBoundary,
    HandshakeState,
    RecordParseState,
    ResumptionObservation,
    TLSAlertObservation,
    TLSEntryPoint,
    TLSSessionAnalysis,
    TLSVersionAnalysis,
)
from ..protocols.reader import DirectionalBuffer
from .forward_secrecy import assess_forward_secrecy
from .handshake import (
    ClientHelloInfo,
    HandshakeMessage,
    HandshakeStream,
    ServerHelloInfo,
    ServerKeyExchangeInfo,
    parse_alert,
    parse_certificate_message,
    parse_client_hello,
    parse_messages,
    parse_server_hello,
    parse_server_key_exchange,
)
from .keyexchange import analyze_key_exchange, code_point
from .records import DirectionRecords, RecordFragment, parse_records
from .registry import (
    REGISTRY_REVISION,
    REGISTRY_SOURCE,
    is_grease,
    lookup_cipher_suite,
    lookup_version,
)
from .wire import TLSParseError

__all__ = ["analyze_tls_session"]

TLS13 = 0x0304
_HANDSHAKE_CLIENT_HELLO = 1
_HANDSHAKE_SERVER_HELLO = 2
_HANDSHAKE_CERTIFICATE = 11
_HANDSHAKE_SERVER_KEY_EXCHANGE = 12
_HANDSHAKE_SERVER_HELLO_DONE = 14
_HANDSHAKE_NEW_SESSION_TICKET = 4

_BASE_LIMITATIONS: tuple[str, ...] = (
    "No TLS record is decrypted and no key material is used or accepted.",
    "Handshake completion cannot be verified passively; what is reported is what was "
    "negotiated and what was visible.",
)


def _entry_points(
    session: TCPSession,
    protocol: ProtocolSessionAnalysis | None,
    client: DirectionalBuffer,
    server: DirectionalBuffer,
) -> tuple[TLSEntryPoint, dict[str, int]] | None:
    """Decide where TLS starts in each direction, reusing the M2 boundaries."""
    if protocol is not None and protocol.upgrade is not None:
        upgrade = protocol.upgrade
        if upgrade.state in {UpgradeState.UPGRADE_ACCEPTED, UpgradeState.TLS_BYTES_OBSERVED}:
            offsets: dict[str, int] = {}
            if upgrade.client_boundary and upgrade.client_boundary.basis == "FIRST_TLS_RECORD":
                offsets[Direction.CLIENT_TO_SERVER.value] = (
                    upgrade.client_boundary.stream_offset
                )
            if upgrade.server_boundary:
                offsets[Direction.SERVER_TO_CLIENT.value] = (
                    upgrade.server_boundary.stream_offset
                )
            if offsets:
                return TLSEntryPoint.STARTTLS_UPGRADE, offsets

    implicit = protocol.implicit_tls if protocol is not None else None
    if implicit is not None and implicit.observed:
        offsets = {}
        if not client.empty:
            offsets[Direction.CLIENT_TO_SERVER.value] = client.runs[0][0]
        if not server.empty:
            offsets[Direction.SERVER_TO_CLIENT.value] = server.runs[0][0]
        return TLSEntryPoint.IMPLICIT, offsets

    # Nothing upstream said this was TLS. Only claim it if a record frames at
    # the very start of a stream.
    from ..protocols.framing import classify_record_header

    offsets = {}
    for direction, buffer in (
        (Direction.CLIENT_TO_SERVER, client),
        (Direction.SERVER_TO_CLIENT, server),
    ):
        if buffer.empty:
            continue
        start = buffer.runs[0][0]
        if classify_record_header(buffer.read(start, 5)) is not None:
            offsets[direction.value] = start
    if offsets:
        return TLSEntryPoint.UNKNOWN, offsets
    return None


def _merged(client: DirectionRecords, server: DirectionRecords) -> list[RecordFragment]:
    """Records from both directions in capture order."""
    fragments = [*client.fragments, *server.fragments]
    fragments.sort(
        key=lambda fragment: (
            fragment.observation.packet_refs[0].packet_number
            if fragment.observation.packet_refs
            else 0,
            fragment.observation.stream_offset,
            fragment.observation.direction.value,
        )
    )
    return fragments


def analyze_tls_session(
    session: TCPSession,
    protocol: ProtocolSessionAnalysis | None,
    client_runs: list[tuple[int, bytes]],
    server_runs: list[tuple[int, bytes]],
    *,
    config: AnalysisConfig,
    capture_id: str,
    trust_store: LoadedTrustStore,
) -> TLSSessionAnalysis | None:
    """Analyse one session's TLS, or return ``None`` when it carries none."""
    client = DirectionalBuffer.build(
        Direction.CLIENT_TO_SERVER, client_runs, session.client_to_server
    )
    server = DirectionalBuffer.build(
        Direction.SERVER_TO_CLIENT, server_runs, session.server_to_client
    )
    entry = _entry_points(session, protocol, client, server)
    if entry is None:
        return None
    entry_point, offsets = entry

    sink = WarningSink(capture_id=capture_id, max_per_code=config.max_warnings_per_code)
    client_records = _parse(client, offsets, Direction.CLIENT_TO_SERVER, config, sink, session)
    server_records = _parse(server, offsets, Direction.SERVER_TO_CLIENT, config, sink, session)
    fragments = _merged(client_records, server_records)

    state = _HandshakeWalk(config=config, sink=sink, session_id=session.session_id)
    state.run(fragments)
    state.finish()

    version = _version_analysis(state)
    selected_version = version.selected_version.value if version.selected_version else None
    suite_analysis = _cipher_analysis(state, selected_version)
    suite = (
        lookup_cipher_suite(state.server_hello.cipher_suite)
        if state.server_hello is not None
        else None
    )
    key_exchange = analyze_key_exchange(
        client_hello=state.client_hello,
        server_hello=state.server_hello,
        server_key_exchange=state.server_key_exchange,
        selected_version=selected_version,
        suite=suite,
        hello_retry_request=state.hello_retry_request,
        evidence_refs=state.evidence_refs(),
    )
    forward_secrecy = assess_forward_secrecy(
        key_exchange=key_exchange,
        suite=suite,
        selected_version=selected_version,
        server_hello_observed=state.server_hello is not None,
        evidence_refs=state.evidence_refs(),
    )
    certificates = _certificates(
        state,
        session=session,
        config=config,
        sink=sink,
        selected_version=selected_version,
        suite=suite,
        trust_store=trust_store,
        protocol=protocol,
    )
    resumption = _resumption(state, selected_version)
    handshake_state = _handshake_state(state, client_records, server_records, selected_version)

    limitations = list(_BASE_LIMITATIONS)
    if state.encrypted_from:
        limitations.append(
            "Plaintext handshake parsing stopped at the encryption boundary; records "
            "after it are framed but never interpreted."
        )

    extensions = state.client_hello.extensions if state.client_hello else None
    return TLSSessionAnalysis(
        session_id=session.session_id,
        capture_id=capture_id,
        entry_point=entry_point,
        entry_offsets=offsets,
        client_record_parse_state=client_records.parse_state,
        server_record_parse_state=server_records.parse_state,
        record_count=len(fragments),
        records=tuple(
            fragment.observation.model_copy(
                update={
                    "encrypted": state.is_encrypted_record(fragment),
                    "body_interpreted": (
                        fragment.observation.direction,
                        fragment.index,
                    )
                    in state.interpreted_records,
                }
            )
            for fragment in fragments
        ),
        messages=tuple(message.observation for message in state.messages),
        encryption_boundaries=state.boundaries(),
        handshake_state=handshake_state,
        version=version,
        cipher_suite=suite_analysis,
        key_exchange=key_exchange,
        forward_secrecy=forward_secrecy,
        certificates=certificates,
        resumption=resumption,
        alerts=tuple(state.alerts),
        server_name_indication=extensions.server_name if extensions else None,
        alpn_offered=extensions.alpn if extensions else (),
        alpn_selected=(
            state.server_hello.extensions.alpn[0]
            if state.server_hello is not None and state.server_hello.extensions.alpn
            else None
        ),
        warnings=sink.collect(),
        limitations=tuple(limitations),
    )


def _parse(
    buffer: DirectionalBuffer,
    offsets: dict[str, int],
    direction: Direction,
    config: AnalysisConfig,
    sink: WarningSink,
    session: TCPSession,
) -> DirectionRecords:
    start = offsets.get(direction.value)
    if start is None or buffer.empty:
        return DirectionRecords(direction=direction, parse_state=RecordParseState.NOT_TLS)
    return parse_records(
        buffer,
        start,
        direction=direction,
        config=config,
        sink=sink,
        session_id=session.session_id,
    )


class _HandshakeWalk:
    """Walks records in capture order, honouring the encryption boundary."""

    def __init__(self, *, config: AnalysisConfig, sink: WarningSink, session_id: str) -> None:
        self.config = config
        self.sink = sink
        self.session_id = session_id
        self.streams = {
            Direction.CLIENT_TO_SERVER: HandshakeStream(Direction.CLIENT_TO_SERVER),
            Direction.SERVER_TO_CLIENT: HandshakeStream(Direction.SERVER_TO_CLIENT),
        }
        self.encrypted_from: dict[Direction, tuple[int, str, PacketReference | None]] = {}
        #: Parsed messages per direction, replaced on every drain because a
        #: message that is incomplete now may complete when the next record
        #: arrives.
        self._parsed: dict[Direction, list[HandshakeMessage]] = {
            Direction.CLIENT_TO_SERVER: [],
            Direction.SERVER_TO_CLIENT: [],
        }
        self._handled: dict[Direction, int] = {
            Direction.CLIENT_TO_SERVER: 0,
            Direction.SERVER_TO_CLIENT: 0,
        }
        #: Keyed by (direction, record index): indices restart per direction,
        #: so a bare index would collide between the two streams.
        self.interpreted_records: set[tuple[Direction, int]] = set()
        self.ambiguous_records: set[tuple[Direction, int]] = set()
        self.alerts: list[TLSAlertObservation] = []
        #: True once anything establishes that this is TLS 1.3 -- a ServerHello
        #: or a HelloRetryRequest. Used so the TLS 1.3 compatibility
        #: ChangeCipherSpec is not read as a TLS 1.2 signal (RFC 8446 §D.4).
        self.tls13_indicated = False
        self.compatibility_ccs = False

        self.client_hello: ClientHelloInfo | None = None
        self.server_hello: ServerHelloInfo | None = None
        self.server_key_exchange: ServerKeyExchangeInfo | None = None
        self.hello_retry_request = False
        self.certificate_message: HandshakeMessage | None = None
        self.server_hello_done = False
        self.new_session_ticket = False
        self.change_cipher_spec: dict[Direction, int] = {}
        self._client_hello_ref: tuple[PacketReference, ...] = ()
        self._server_hello_ref: tuple[PacketReference, ...] = ()

    # -- encryption boundary ------------------------------------------------
    def _mark_encrypted(
        self, direction: Direction, offset: int, reason: str, ref: PacketReference | None
    ) -> None:
        if direction not in self.encrypted_from:
            self.encrypted_from[direction] = (offset, reason, ref)

    def is_encrypted_record(self, fragment: RecordFragment) -> bool:
        entry = self.encrypted_from.get(fragment.observation.direction)
        if entry is None:
            return False
        return fragment.observation.stream_offset >= entry[0]

    def boundaries(self) -> tuple[EncryptionBoundary, ...]:
        result = []
        for direction in (Direction.CLIENT_TO_SERVER, Direction.SERVER_TO_CLIENT):
            entry = self.encrypted_from.get(direction)
            if entry is None:
                result.append(
                    EncryptionBoundary(
                        direction=direction,
                        stream_offset=None,
                        reason="NOT_ENCRYPTED",
                        status=EvidenceStatus.OBSERVED,
                    )
                )
            else:
                offset, reason, ref = entry
                result.append(
                    EncryptionBoundary(
                        direction=direction,
                        stream_offset=offset,
                        reason=reason,
                        packet_ref=ref,
                        status=EvidenceStatus.OBSERVED,
                    )
                )
        return tuple(result)

    # -- walking ------------------------------------------------------------
    @property
    def messages(self) -> list[HandshakeMessage]:
        """All parsed messages, in capture order."""
        combined = [
            message
            for direction in (Direction.CLIENT_TO_SERVER, Direction.SERVER_TO_CLIENT)
            for message in self._parsed[direction]
        ]
        combined.sort(
            key=lambda message: (
                message.observation.packet_refs[0].packet_number
                if message.observation.packet_refs
                else 0,
                message.observation.stream_offset,
            )
        )
        return combined

    def run(self, fragments: list[RecordFragment]) -> None:
        for fragment in fragments:
            observation = fragment.observation
            direction = observation.direction
            if self.is_encrypted_record(fragment):
                if observation.content_type_name is TLSContentType.ALERT:
                    self._encrypted_alert(fragment)
                continue

            if observation.ambiguous:
                # Overlapping TCP segments disagreed about these bytes. They
                # are framed and reported, but never parsed: an ambiguous byte
                # is not evidence of a negotiated parameter.
                self.ambiguous_records.add((direction, fragment.index))
                self.sink.add(
                    WarningCode.TLS_RECORD_AMBIGUOUS,
                    f"A {direction.value} TLS record at stream offset "
                    f"{observation.stream_offset} lies in a range where overlapping TCP "
                    "segments disagreed, so its contents are not interpreted.",
                    severity=Severity.ERROR,
                    session_id=self.session_id,
                    packet_refs=observation.packet_refs,
                    stream_offset=observation.stream_offset,
                )
                continue

            if observation.content_type_name is TLSContentType.CHANGE_CIPHER_SPEC:
                self.change_cipher_spec[direction] = observation.stream_offset
                if self.tls13_indicated or self._selected_version() == TLS13:
                    # RFC 8446 §D.4: a TLS 1.3 peer may emit a ChangeCipherSpec
                    # purely for middlebox compatibility. It carries no protocol
                    # meaning and is not evidence of a TLS 1.2 handshake.
                    self.compatibility_ccs = True
                else:
                    self._mark_encrypted(
                        direction,
                        observation.end_offset,
                        "TLS12_CHANGE_CIPHER_SPEC",
                        observation.packet_refs[-1] if observation.packet_refs else None,
                    )
                continue

            if observation.content_type_name is TLSContentType.ALERT:
                self._plaintext_alert(fragment)
                continue

            if observation.content_type_name is TLSContentType.APPLICATION_DATA:
                # In TLS 1.3 this carries encrypted handshake data; in TLS 1.2
                # it is encrypted application traffic. Never interpreted.
                self._mark_encrypted(
                    direction,
                    observation.stream_offset,
                    "APPLICATION_DATA_OBSERVED",
                    observation.packet_refs[0] if observation.packet_refs else None,
                )
                continue

            if observation.content_type_name is not TLSContentType.HANDSHAKE:
                continue

            stream = self.streams[direction]
            if not stream.append(fragment, self.config.max_tls_handshake_bytes):
                self.sink.add(
                    WarningCode.LIMIT_TLS_HANDSHAKE_BYTES,
                    f"The {direction.value} handshake buffer reached the "
                    f"{self.config.max_tls_handshake_bytes}-byte limit; later handshake "
                    "records are not reassembled.",
                    severity=Severity.ERROR,
                    session_id=self.session_id,
                    limit=self.config.max_tls_handshake_bytes,
                )
                continue
            self.interpreted_records.add((direction, fragment.index))
            self._drain(direction)

    def _drain(self, direction: Direction, *, final: bool = False) -> None:
        """Re-parse a direction's buffer and handle newly complete messages.

        The whole buffer is re-parsed rather than continued, because a message
        that was incomplete when the previous record arrived may be complete
        now. Only messages that have become complete are handled, and each is
        handled exactly once.
        """
        stream = self.streams[direction]
        parsed = parse_messages(
            stream,
            config=self.config,
            sink=self.sink,
            session_id=self.session_id,
            warn_incomplete=final,
        )
        self._parsed[direction] = parsed
        index = self._handled[direction]
        while index < len(parsed) and parsed[index].observation.complete:
            self._handle(parsed[index], direction)
            index += 1
        self._handled[direction] = index

    def finish(self) -> None:
        """Final pass: emit any trailing incomplete message and warn about it."""
        for direction in (Direction.CLIENT_TO_SERVER, Direction.SERVER_TO_CLIENT):
            if self.streams[direction].fragments:
                self._drain(direction, final=True)

    def _handle(self, message: HandshakeMessage, direction: Direction) -> None:
        kind = message.observation.message_type
        if not message.observation.complete:
            return
        try:
            if kind == _HANDSHAKE_CLIENT_HELLO and self.client_hello is None:
                self.client_hello = parse_client_hello(message.body)
                self._client_hello_ref = message.observation.packet_refs
                # The client's next flight is encrypted once TLS 1.3 is chosen;
                # the boundary is set when the ServerHello confirms the version.
            elif kind == _HANDSHAKE_SERVER_HELLO and self.server_hello is None:
                info = parse_server_hello(message.body)
                self._server_hello_ref = message.observation.packet_refs
                if info.is_hello_retry_request:
                    self.hello_retry_request = True
                    if info.extensions.selected_version == TLS13:
                        self.tls13_indicated = True
                    return
                self.server_hello = info
                if self._selected_version() == TLS13:
                    self.tls13_indicated = True
                    self._apply_tls13_boundary(message)
            elif kind == _HANDSHAKE_SERVER_KEY_EXCHANGE:
                suite = (
                    lookup_cipher_suite(self.server_hello.cipher_suite)
                    if self.server_hello
                    else None
                )
                family = suite.key_exchange.value if suite else "UNKNOWN"
                self.server_key_exchange = parse_server_key_exchange(message.body, family)
            elif kind == _HANDSHAKE_CERTIFICATE and self.certificate_message is None:
                self.certificate_message = message
            elif kind == _HANDSHAKE_SERVER_HELLO_DONE:
                self.server_hello_done = True
            elif kind == _HANDSHAKE_NEW_SESSION_TICKET:
                self.new_session_ticket = True
        except TLSParseError as error:
            self.sink.add(
                WarningCode.TLS_HANDSHAKE_MALFORMED,
                f"A {direction.value} {message.observation.message_type_name} message at "
                f"stream offset {message.observation.stream_offset} is structurally "
                f"invalid and was not interpreted: {error}",
                severity=Severity.ERROR,
                session_id=self.session_id,
                packet_refs=message.observation.packet_refs,
                stream_offset=message.observation.stream_offset,
            )

    def _apply_tls13_boundary(self, server_hello: HandshakeMessage) -> None:
        """RFC 8446 §2: everything after the ServerHello is encrypted."""
        boundary = server_hello.observation.end_offset
        ref = (
            server_hello.observation.packet_refs[-1]
            if server_hello.observation.packet_refs
            else None
        )
        self._mark_encrypted(
            Direction.SERVER_TO_CLIENT, boundary, "TLS13_AFTER_SERVER_HELLO", ref
        )
        client_boundary = (
            self.streams[Direction.CLIENT_TO_SERVER].fragments[-1].stream_offset
            + self.streams[Direction.CLIENT_TO_SERVER].fragments[-1].length
            if self.streams[Direction.CLIENT_TO_SERVER].fragments
            else 0
        )
        self._mark_encrypted(
            Direction.CLIENT_TO_SERVER,
            client_boundary,
            "TLS13_AFTER_SERVER_HELLO",
            self._client_hello_ref[-1] if self._client_hello_ref else None,
        )
        self.sink.add(
            WarningCode.TLS_HANDSHAKE_ENCRYPTED,
            "TLS 1.3 was negotiated, so every handshake message after the ServerHello -- "
            "including EncryptedExtensions, Certificate and Finished -- is encrypted "
            "under handshake traffic keys and cannot be recovered from a passive capture.",
            severity=Severity.INFO,
            session_id=self.session_id,
            packet_refs=server_hello.observation.packet_refs,
        )

    def _selected_version(self) -> int | None:
        if self.server_hello is None:
            return None
        extension = self.server_hello.extensions.selected_version
        return extension if extension is not None else self.server_hello.legacy_version

    def _plaintext_alert(self, fragment: RecordFragment) -> None:
        level, level_name, description, name = parse_alert(fragment.body)
        self.alerts.append(
            TLSAlertObservation(
                direction=fragment.observation.direction,
                stream_offset=fragment.observation.stream_offset,
                level=level,
                level_name=level_name,
                description=description,
                description_name=name,
                encrypted=False,
                packet_refs=fragment.observation.packet_refs,
            )
        )
        self.sink.add(
            WarningCode.TLS_ALERT_OBSERVED,
            f"A plaintext TLS alert was observed in the {fragment.observation.direction.value} "
            f"direction at stream offset {fragment.observation.stream_offset}: "
            f"{level_name or 'unknown level'} / {name or f'code {description}'}.",
            severity=Severity.INFO,
            session_id=self.session_id,
            packet_refs=fragment.observation.packet_refs,
        )

    def _encrypted_alert(self, fragment: RecordFragment) -> None:
        self.alerts.append(
            TLSAlertObservation(
                direction=fragment.observation.direction,
                stream_offset=fragment.observation.stream_offset,
                encrypted=True,
                packet_refs=fragment.observation.packet_refs,
                status=EvidenceStatus.INFERRED,
                limitations=(
                    "This alert arrived after the encryption boundary, so only its record "
                    "framing is observable; its level and description are not readable.",
                ),
            )
        )

    def evidence_refs(self) -> tuple[PacketReference, ...]:
        seen: dict[int, PacketReference] = {}
        for refs in (self._client_hello_ref, self._server_hello_ref):
            for ref in refs:
                seen.setdefault(ref.packet_number, ref)
        return tuple(seen[number] for number in sorted(seen))


def _version_analysis(state: _HandshakeWalk) -> TLSVersionAnalysis:
    limitations: list[str] = []
    client_legacy = None
    offered: tuple[CodePointRef, ...] = ()
    offered_source = None

    if state.client_hello is not None:
        client_legacy = code_point(
            state.client_hello.legacy_version,
            lookup_version(state.client_hello.legacy_version),
        )
        extension_versions = state.client_hello.extensions.offered_versions
        if extension_versions:
            offered = tuple(
                code_point(value, lookup_version(value))
                for value in extension_versions
                if not is_grease(value)
            )
            offered_source = "SUPPORTED_VERSIONS_EXTENSION"
        else:
            offered = (client_legacy,)
            offered_source = "LEGACY_VERSION"

    server_legacy = None
    selected = None
    selected_source = None
    status = EvidenceStatus.UNKNOWN

    if state.server_hello is not None:
        server_legacy = code_point(
            state.server_hello.legacy_version,
            lookup_version(state.server_hello.legacy_version),
        )
        extension = state.server_hello.extensions.selected_version
        if extension is not None:
            selected = code_point(extension, lookup_version(extension))
            selected_source = "SUPPORTED_VERSIONS_EXTENSION"
        else:
            selected = server_legacy
            selected_source = "LEGACY_VERSION"
        status = EvidenceStatus.OBSERVED
        if selected.value == TLS13:
            limitations.append(
                "TLS 1.3 was identified from the ServerHello supported_versions extension "
                "(RFC 8446 §4.2.1); the legacy_version field reads 0x0303 by design and is "
                "never used to identify the version."
            )
    else:
        limitations.append(
            "No ServerHello was observed, so no version was negotiated. The client's "
            "offered versions are capability only; the highest offered version is never "
            "reported as selected."
        )

    return TLSVersionAnalysis(
        client_legacy_version=client_legacy,
        offered_versions=offered,
        offered_source=offered_source,
        server_legacy_version=server_legacy,
        selected_version=selected,
        selected_source=selected_source,
        negotiation_status=status,
        evidence_refs=state.evidence_refs(),
        limitations=tuple(limitations),
    )


def _cipher_analysis(state: _HandshakeWalk, selected_version: int | None) -> CipherSuiteAnalysis:
    limitations: list[str] = []
    offered: tuple[CodePointRef, ...] = ()
    grease_count = 0
    unknown_count = 0

    if state.client_hello is not None:
        refs = []
        for value in state.client_hello.cipher_suites[:256]:
            info = lookup_cipher_suite(value)
            ref = code_point(value, info.name if info else None)
            if ref.grease:
                grease_count += 1
            elif not ref.known:
                unknown_count += 1
            refs.append(ref)
        offered = tuple(refs)
        if unknown_count:
            limitations.append(
                f"{unknown_count} offered cipher suite(s) are not in this build's "
                "registry and are reported by their numeric identifier only."
            )

    selected = None
    status = EvidenceStatus.UNKNOWN
    decomposition_applicable = True
    key_exchange = authentication = encryption = mac = None
    aead = None

    if state.server_hello is not None:
        info = lookup_cipher_suite(state.server_hello.cipher_suite)
        selected = code_point(
            state.server_hello.cipher_suite, info.name if info else None
        )
        status = EvidenceStatus.OBSERVED
        if selected_version == TLS13:
            decomposition_applicable = False
            encryption = info.encryption if info else None
            mac = info.mac_or_prf if info else None
            aead = info.aead if info else None
            limitations.append(
                "TLS 1.3 cipher suites encode only an AEAD algorithm and a hash "
                "(RFC 8446 §B.4). Key exchange and authentication are NOT encoded in the "
                "suite and are reported from the key_share and signature_algorithms "
                "extensions instead."
            )
        elif info is not None:
            key_exchange = info.key_exchange.value
            authentication = info.authentication.value
            encryption = info.encryption
            mac = info.mac_or_prf
            aead = info.aead
        else:
            limitations.append(
                "The selected cipher suite is not in this build's registry, so its "
                "components are not described. Nothing is inferred from the numeric value."
            )
    else:
        limitations.append(
            "No ServerHello was observed. The offered suites describe what the client "
            "would have accepted; none of them is reported as negotiated."
        )

    return CipherSuiteAnalysis(
        offered=offered,
        offered_count=len(offered),
        grease_count=grease_count,
        unknown_offered_count=unknown_count,
        selected=selected,
        selection_status=status,
        decomposition_applicable=decomposition_applicable,
        key_exchange=key_exchange,
        authentication=authentication,
        encryption=encryption,
        mac_or_prf=mac,
        aead=aead,
        registry_source=REGISTRY_SOURCE,
        registry_revision=REGISTRY_REVISION,
        evidence_refs=state.evidence_refs(),
        limitations=tuple(limitations),
    )


def _certificates(
    state: _HandshakeWalk,
    *,
    session: TCPSession,
    config: AnalysisConfig,
    sink: WarningSink,
    selected_version: int | None,
    suite: Any,
    trust_store: LoadedTrustStore,
    protocol: ProtocolSessionAnalysis | None,
) -> CertificateInventory:
    if state.certificate_message is None:
        return _absent_certificates(state, selected_version, suite, trust_store, session)

    message = state.certificate_message
    capture_time = _certificate_time(message, session)
    try:
        blobs, notes = parse_certificate_message(
            message.body,
            tls13=selected_version == TLS13,
            max_certificates=config.max_certificates_per_chain,
            max_certificate_bytes=config.max_certificate_bytes,
        )
    except TLSParseError as error:
        sink.add(
            WarningCode.CERTIFICATE_PARSE_FAILED,
            f"The Certificate message at stream offset {message.observation.stream_offset} "
            f"is structurally invalid and no certificate could be extracted: {error}",
            severity=Severity.ERROR,
            session_id=session.session_id,
            packet_refs=message.observation.packet_refs,
        )
        return CertificateInventory(
            visibility=CertificateVisibility.PARSE_FAILED,
            visibility_explanation=(
                "A Certificate message was present but its certificate_list structure "
                f"could not be decoded: {error}"
            ),
            validation=validate_chain(
                [],
                [],
                capture_time=capture_time,
                trust_store=trust_store,
                reference_identity=None,
                reference_identity_source="NONE",
                observed_sni=None,
            ),
        )

    observations: list[CertificateObservation] = []
    decoded: list[Any] = []
    errors: list[str] = []
    for position, der in enumerate(blobs):
        observation, certificate, parse_error = parse_certificate(
            der,
            chain_position=position,
            direction=Direction.SERVER_TO_CLIENT,
            stream_offset=message.observation.stream_offset,
            packet_refs=message.observation.packet_refs,
        )
        if observation is None or certificate is None:
            errors.append(f"certificate {position}: {parse_error}")
            sink.add(
                WarningCode.CERTIFICATE_PARSE_FAILED,
                f"Certificate {position} in the chain could not be decoded: {parse_error}",
                severity=Severity.ERROR,
                session_id=session.session_id,
                packet_refs=message.observation.packet_refs,
            )
            continue
        observations.append(observation)
        decoded.append(certificate)

    if not observations:
        visibility = (
            CertificateVisibility.PARSER_UNAVAILABLE
            if not CRYPTOGRAPHY_AVAILABLE
            else CertificateVisibility.PARSE_FAILED
        )
        if not CRYPTOGRAPHY_AVAILABLE:
            explanation = (
                "The cryptography library is not installed, so certificates cannot be "
                "decoded."
            )
        elif notes:
            explanation = (
                "A Certificate message was observed but no certificate was decoded from "
                "it because a configured limit was reached: " + " ".join(notes)
            )
        else:
            explanation = (
                "A Certificate message was observed but no certificate in it could be "
                "decoded."
            )
        return CertificateInventory(
            visibility=visibility,
            visibility_explanation=explanation,
            truncated=bool(notes),
            limitations=(*notes, *errors),
            validation=validate_chain(
                [],
                [],
                capture_time=capture_time,
                trust_store=trust_store,
                reference_identity=None,
                reference_identity_source="NONE",
                observed_sni=None,
            ),
        )

    observed_sni = (
        state.client_hello.extensions.server_name if state.client_hello else None
    )
    identity, identity_source = _reference_identity(config, observed_sni)
    validation = validate_chain(
        observations,
        decoded,
        capture_time=capture_time,
        trust_store=trust_store,
        reference_identity=identity,
        reference_identity_source=identity_source,
        observed_sni=observed_sni,
        assess_current_time=config.assess_certificates_at_current_time,
    )
    _date_warnings(sink, session.session_id, observations[0], validation)

    return CertificateInventory(
        visibility=CertificateVisibility.OBSERVED,
        visibility_explanation=(
            f"A plaintext Certificate message carrying {len(observations)} certificate(s) "
            "was observed and decoded."
        ),
        certificates=tuple(observations),
        validation=validation,
        chain_length=len(observations),
        truncated=bool(notes),
        limitations=(*notes, *errors),
    )


def _reference_identity(
    config: AnalysisConfig, observed_sni: str | None
) -> tuple[str | None, str]:
    if config.expected_server_identity:
        return config.expected_server_identity, "OPERATOR_SUPPLIED"
    if config.trust_observed_sni_as_identity and observed_sni:
        return observed_sni, "OBSERVED_SNI_EXPLICITLY_TRUSTED"
    return None, "NONE"


def _certificate_time(message: HandshakeMessage, session: TCPSession) -> datetime | None:
    """Prefer the timestamp of the packet that actually carried the certificate."""
    if message.observation.packet_refs:
        return message.observation.packet_refs[0].timestamp
    return session.first_packet.timestamp


def _date_warnings(
    sink: WarningSink, session_id: str, leaf: CertificateObservation, validation: Any
) -> None:
    check = validation.validity_dates_checked
    if check.status.value != "FAILED" or check.reference_time is None:
        return
    expired = check.reference_time > leaf.not_valid_after
    sink.add(
        WarningCode.CERTIFICATE_EXPIRED_AT_CAPTURE
        if expired
        else WarningCode.CERTIFICATE_NOT_YET_VALID_AT_CAPTURE,
        check.explanation,
        session_id=session_id,
        packet_refs=leaf.packet_refs,
        fingerprint=leaf.sha256_fingerprint,
    )


def _absent_certificates(
    state: _HandshakeWalk,
    selected_version: int | None,
    suite: Any,
    trust_store: LoadedTrustStore,
    session: TCPSession,
) -> CertificateInventory:
    """Explain *why* no certificate is available. Absence is not failure."""
    if suite is not None and suite.authentication.value == "ANONYMOUS":
        visibility = CertificateVisibility.NOT_APPLICABLE_ANONYMOUS
        explanation = (
            f"The negotiated suite {suite.name} is anonymous, so no certificate is sent. "
            "This is not a missing certificate."
        )
    elif selected_version == TLS13:
        visibility = CertificateVisibility.ENCRYPTED_TLS13
        explanation = (
            "TLS 1.3 was negotiated. The Certificate message is sent after the "
            "ServerHello and is encrypted under handshake traffic keys (RFC 8446 §2), so "
            "it cannot be recovered from a passive capture without key material. This is "
            "a permanent limit of passive analysis, not a missing certificate."
        )
    elif state.hello_retry_request and state.server_hello is None:
        visibility = CertificateVisibility.NOT_OBSERVED
        explanation = (
            "The server answered with a HelloRetryRequest, so the negotiation restarted "
            "and never reached the point where a certificate would be sent. Any "
            "ChangeCipherSpec here is the TLS 1.3 middlebox-compatibility record "
            "(RFC 8446 §D.4), not evidence of a TLS 1.2 handshake."
        )
    elif Direction.SERVER_TO_CLIENT in state.change_cipher_spec and not state.tls13_indicated:
        visibility = CertificateVisibility.ENCRYPTED_AFTER_CCS
        explanation = (
            "The server sent ChangeCipherSpec before any plaintext Certificate message "
            "was observed, which is the expected shape of an abbreviated (resumed) "
            "TLS 1.2 handshake. No new certificate is sent in that case."
        )
    elif state.server_hello is not None:
        visibility = CertificateVisibility.NOT_OBSERVED
        explanation = (
            "A ServerHello was observed but no Certificate message followed in the "
            "captured plaintext. The capture may end before it, or the handshake may be "
            "abbreviated."
        )
    else:
        visibility = CertificateVisibility.NOT_OBSERVED
        explanation = (
            "No ServerHello was observed, so the handshake never reached the point where "
            "a certificate would be sent."
        )

    return CertificateInventory(
        visibility=visibility,
        visibility_explanation=explanation,
        validation=validate_chain(
            [],
            [],
            capture_time=session.first_packet.timestamp,
            trust_store=trust_store,
            reference_identity=None,
            reference_identity_source="NONE",
            observed_sni=state.client_hello.extensions.server_name
            if state.client_hello
            else None,
        ),
        limitations=(
            "A session without a certificate message is not a certificate failure; the "
            "visibility field states the reason.",
        ),
    )


def _resumption(state: _HandshakeWalk, selected_version: int | None) -> ResumptionObservation:
    if selected_version == TLS13:
        offered = state.client_hello.extensions.psk_offered if state.client_hello else False
        selected = (
            state.server_hello.extensions.server_selected_psk_identity is not None
            if state.server_hello
            else None
        )
        likely = bool(offered and selected) if selected is not None else None
        return ResumptionObservation(
            tls13_psk_offered=offered,
            tls13_psk_selected=selected,
            new_session_ticket_observed=state.new_session_ticket,
            likely_resumed=likely,
            explanation=(
                "The client offered a pre-shared key and the server selected one, which "
                "is how TLS 1.3 resumption appears on the wire (RFC 8446 §2.2)."
                if likely
                else "No pre-shared key was selected, so this is a full handshake."
                if selected is not None
                else "No ServerHello was observed, so resumption cannot be determined."
            ),
        )

    client_id = state.client_hello.session_id if state.client_hello else b""
    server_id = state.server_hello.session_id if state.server_hello else b""
    echoed = bool(client_id) and client_id == server_id
    return ResumptionObservation(
        tls12_session_id_echoed=echoed if state.server_hello else None,
        tls12_session_id_length=len(server_id) if state.server_hello else None,
        new_session_ticket_observed=state.new_session_ticket,
        likely_resumed=echoed if state.server_hello else None,
        explanation=(
            "The server echoed the client's non-empty session identifier, which indicates "
            "an abbreviated (resumed) TLS 1.2 handshake (RFC 5246 §7.3)."
            if echoed
            else "The server did not echo the client's session identifier, so this is a "
            "full handshake."
            if state.server_hello
            else "No ServerHello was observed, so resumption cannot be determined."
        ),
        limitations=(
            "Session identifiers themselves are not recorded; only whether the server's "
            "echo matched the client's offer.",
        ),
    )


def _handshake_state(
    state: _HandshakeWalk,
    client_records: DirectionRecords,
    server_records: DirectionRecords,
    selected_version: int | None,
) -> HandshakeState:
    degraded = {
        RecordParseState.ALIGNMENT_LOST_AT_GAP,
        RecordParseState.MALFORMED_RECORD,
        RecordParseState.AMBIGUOUS_BYTES,
    }
    if any(alert.level_name == "fatal" for alert in state.alerts):
        return HandshakeState.ABORTED_BY_ALERT
    if client_records.parse_state in degraded or server_records.parse_state in degraded:
        return HandshakeState.INDETERMINATE
    if state.hello_retry_request and state.server_hello is None:
        return HandshakeState.HELLO_RETRY_REQUESTED
    if state.server_hello is None:
        return (
            HandshakeState.CLIENT_HELLO_ONLY
            if state.client_hello is not None
            else HandshakeState.NOT_OBSERVED
        )
    if state.client_hello is None:
        return HandshakeState.SERVER_HELLO_WITHOUT_CLIENT_HELLO
    if selected_version == TLS13:
        return HandshakeState.NEGOTIATED_THEN_ENCRYPTED
    if state.server_hello_done:
        return HandshakeState.SERVER_FLIGHT_COMPLETE
    if Direction.SERVER_TO_CLIENT in state.change_cipher_spec:
        return HandshakeState.NEGOTIATED_THEN_ENCRYPTED
    return HandshakeState.NEGOTIATED
