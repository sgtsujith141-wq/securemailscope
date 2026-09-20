"""TCP session engine: turns a packet stream into reconstructed connections.

Connection identity
-------------------
Flows are keyed by the normalised 5-tuple, but a key may host *several*
connections over the life of a capture.  A new connection is started when a
client SYN arrives at a key that already carries a connection which has
progressed past its own SYN -- a different initial sequence number, any
payload, a FIN or a RST all qualify.  Successive connections therefore share a
``flow_id`` but get distinct ``session_id`` values and are never merged.

Role assignment
---------------
Client and server are ``OBSERVED`` when a SYN or SYN/ACK fixes them.  In a
midstream capture they are ``INFERRED``: a recognised service port wins,
otherwise the endpoint that sent the first observed packet is taken to be the
client.  The basis is always recorded, and the session carries a
``MIDSTREAM_SESSION`` diagnostic.
"""

from __future__ import annotations

from ..config import AnalysisConfig
from ..diagnostics import WarningSink
from ..ingestion.dissect import ParsedPacket, TCPFlags
from ..models.evidence import EvidenceStatus, PacketReference, Severity, WarningCode
from ..models.tcp import (
    AddressFamily,
    Direction,
    Endpoint,
    HandshakeInfo,
    SessionCompleteness,
    TCPFlow,
    TCPSession,
    TerminationInfo,
    TerminationReason,
)
from ..protocols.hints import hint_for_port, is_service_port
from .budget import ByteBudget
from .flows import FlowKey, flow_id_for, normalize, session_id_for
from .reassembly import DirectionalReassembler

__all__ = ["TCPSessionEngine"]


class _SessionState:
    """Mutable accumulator for one connection."""

    def __init__(
        self,
        *,
        session_id: str,
        capture_id: str,
        flow: TCPFlow,
        instance: int,
        config: AnalysisConfig,
        sink: WarningSink,
        global_budget: ByteBudget,
    ) -> None:
        self.session_id = session_id
        self.capture_id = capture_id
        self.flow = flow
        self.instance = instance
        self._sink = sink
        self.budget = ByteBudget(config.max_session_payload_bytes)

        common = {
            "config": config,
            "sink": sink,
            "session_budget": self.budget,
            "global_budget": global_budget,
            "session_id": session_id,
        }
        self.c2s = DirectionalReassembler(
            direction=Direction.CLIENT_TO_SERVER,
            source=flow.client,
            destination=flow.server,
            **common,  # type: ignore[arg-type]
        )
        self.s2c = DirectionalReassembler(
            direction=Direction.SERVER_TO_CLIENT,
            source=flow.server,
            destination=flow.client,
            **common,  # type: ignore[arg-type]
        )

        self.packet_count = 0
        self.first_packet: PacketReference | None = None
        self.last_packet: PacketReference | None = None

        self.syn_observed = False
        self.syn_ack_observed = False
        self.handshake_ack_observed = False
        self.client_isn: int | None = None
        self.server_isn: int | None = None
        self.syn_packet: PacketReference | None = None
        self.syn_ack_packet: PacketReference | None = None

        self.client_fin: PacketReference | None = None
        self.server_fin: PacketReference | None = None
        self.reset_packet: PacketReference | None = None
        self.saw_payload = False
        self.closed = False

    def is_from_client(self, packet: ParsedPacket) -> bool:
        return packet.src_ip == self.flow.client.ip and packet.src_port == self.flow.client.port

    def observe(self, packet: ParsedPacket, ref: PacketReference) -> None:
        self.packet_count += 1
        if self.first_packet is None:
            self.first_packet = ref
        self.last_packet = ref

        from_client = self.is_from_client(packet)
        stream = self.c2s if from_client else self.s2c
        peer = self.s2c if from_client else self.c2s

        if packet.flag(TCPFlags.SYN) and not packet.flag(TCPFlags.ACK):
            if not self.syn_observed:
                self.syn_observed = True
                self.client_isn = packet.seq
                self.syn_packet = ref
        elif packet.flag(TCPFlags.SYN) and packet.flag(TCPFlags.ACK):
            if not self.syn_ack_observed:
                self.syn_ack_observed = True
                self.server_isn = packet.seq
                self.syn_ack_packet = ref
        elif (
            packet.flag(TCPFlags.ACK)
            and from_client
            and self.syn_ack_observed
            and not self.handshake_ack_observed
        ):
            self.handshake_ack_observed = True

        if packet.flag(TCPFlags.FIN):
            if from_client and self.client_fin is None:
                self.client_fin = ref
            elif not from_client and self.server_fin is None:
                self.server_fin = ref
        if packet.flag(TCPFlags.RST) and self.reset_packet is None:
            self.reset_packet = ref

        if packet.payload:
            self.saw_payload = True

        stream.observe(packet, ref)
        if packet.flag(TCPFlags.ACK):
            peer.note_peer_ack(packet.ack)

        if self.reset_packet is not None or (
            self.client_fin is not None and self.server_fin is not None
        ):
            self.closed = True

    # -- result ------------------------------------------------------------
    def _termination(self) -> TerminationInfo:
        if self.reset_packet is not None:
            reason = TerminationReason.RESET
        elif self.client_fin is not None and self.server_fin is not None:
            reason = TerminationReason.FIN_BOTH_DIRECTIONS
        elif self.client_fin is not None or self.server_fin is not None:
            reason = TerminationReason.FIN_ONE_DIRECTION
        else:
            reason = TerminationReason.NOT_OBSERVED
        return TerminationInfo(
            reason=reason,
            client_fin=self.client_fin,
            server_fin=self.server_fin,
            reset_packet=self.reset_packet,
        )

    def finalize(self) -> TCPSession:
        c2s = self.c2s.finalize()
        s2c = self.s2c.finalize()
        termination = self._termination()
        handshake = HandshakeInfo(
            syn_observed=self.syn_observed,
            syn_ack_observed=self.syn_ack_observed,
            ack_observed=self.handshake_ack_observed,
            client_isn=self.client_isn,
            server_isn=self.server_isn,
            syn_packet=self.syn_packet,
            syn_ack_packet=self.syn_ack_packet,
        )

        notes: list[str] = []
        if c2s.truncated_by_limit or s2c.truncated_by_limit:
            notes.append("Reconstruction stopped early because a payload or segment limit "
                         "was reached; byte counts are lower bounds.")
            completeness = SessionCompleteness.TRUNCATED
        elif not self.syn_observed:
            notes.append("No client SYN was observed: the capture began after this "
                         "connection was already established.")
            completeness = SessionCompleteness.MIDSTREAM
        else:
            completeness = SessionCompleteness.COMPLETE

        if not self.syn_ack_observed and self.syn_observed:
            notes.append("No SYN/ACK was observed; the server's side of the handshake is "
                         "missing from this capture.")
        if c2s.gaps or s2c.gaps:
            notes.append(
                f"{len(c2s.gaps) + len(s2c.gaps)} gap(s) in the reconstructed data: the "
                "streams are not contiguous."
            )
        if termination.reason in (
            TerminationReason.NOT_OBSERVED,
            TerminationReason.FIN_ONE_DIRECTION,
        ):
            notes.append(
                f"Connection termination was not fully observed ({termination.reason.value})."
            )
        if c2s.overlap_conflicts or s2c.overlap_conflicts:
            notes.append(
                "Overlapping segments delivered conflicting bytes; the reconstructed stream "
                "is one of several possible interpretations."
            )

        if completeness is SessionCompleteness.COMPLETE and len(notes) > 0:
            completeness = SessionCompleteness.PARTIAL

        server_port = self.flow.server.port
        hint = hint_for_port(
            server_port,
            capture_id=self.capture_id,
            session_id=self.session_id,
            packet_ref=self.first_packet,
        )

        if completeness is SessionCompleteness.MIDSTREAM:
            self._sink.add(
                WarningCode.MIDSTREAM_SESSION,
                f"Session {self.session_id} has no observed SYN; client/server roles are "
                "INFERRED and the start of the data streams may be missing.",
                severity=Severity.INFO,
                session_id=self.session_id,
                packet_refs=(self.first_packet,) if self.first_packet else (),
            )
        if termination.reason is TerminationReason.NOT_OBSERVED:
            self._sink.add(
                WarningCode.NO_TERMINATION_OBSERVED,
                f"Session {self.session_id} has no observed FIN or RST; the connection may "
                "have continued past the end of this capture.",
                severity=Severity.INFO,
                session_id=self.session_id,
            )

        assert self.first_packet is not None and self.last_packet is not None
        return TCPSession(
            session_id=self.session_id,
            capture_id=self.capture_id,
            flow=self.flow,
            flow_instance=self.instance,
            first_packet=self.first_packet,
            last_packet=self.last_packet,
            packet_count=self.packet_count,
            handshake=handshake,
            termination=termination,
            completeness=completeness,
            completeness_notes=tuple(notes),
            client_to_server=c2s,
            server_to_client=s2c,
            protocol_hint=hint,
        )


class TCPSessionEngine:
    """Consumes dissected packets and produces reconstructed sessions."""

    def __init__(self, *, capture_id: str, config: AnalysisConfig, sink: WarningSink) -> None:
        self._capture_id = capture_id
        self._config = config
        self._sink = sink
        self._global_budget = ByteBudget(config.max_total_payload_bytes)
        self._active: dict[FlowKey, _SessionState] = {}
        self._completed: list[_SessionState] = []
        self._instances: dict[FlowKey, int] = {}
        self._order: list[_SessionState] = []
        #: Flow keys turned away by a session limit. Once a connection has
        #: been refused, its later packets are refused too: admitting them
        #: when capacity happens to free up would emit a session that looks
        #: midstream because of *our* limit, not because of the capture.
        self._refused_keys: set[FlowKey] = set()
        self.refused_packet_count = 0
        self.tuple_reuse_count = 0

    @property
    def open_session_count(self) -> int:
        return sum(1 for state in self._active.values() if not state.closed)

    @property
    def session_count(self) -> int:
        return len(self._order)

    def observe(self, packet: ParsedPacket) -> None:
        ref = PacketReference.create(packet.packet_number, packet.timestamp_ns)
        source = Endpoint(ip=packet.src_ip, port=packet.src_port)
        destination = Endpoint(ip=packet.dst_ip, port=packet.dst_port)
        key = normalize(source, destination)

        if key in self._refused_keys:
            self.refused_packet_count += 1
            return

        state = self._active.get(key)
        if state is not None and self._starts_new_connection(state, packet):
            self._completed.append(state)
            del self._active[key]
            self.tuple_reuse_count += 1
            self._sink.add(
                WarningCode.TUPLE_REUSE,
                f"A new TCP connection reuses the 5-tuple of session {state.session_id}; "
                "the two connections are reported separately and are never merged.",
                severity=Severity.INFO,
                session_id=state.session_id,
                packet_refs=(ref,),
                previous_session_id=state.session_id,
            )
            state = None

        if state is None:
            state = self._create(key, packet, ref, source, destination)
            if state is None:
                self._refused_keys.add(key)
                self.refused_packet_count += 1
                return
            self._active[key] = state

        state.observe(packet, ref)

    @staticmethod
    def _starts_new_connection(state: _SessionState, packet: ParsedPacket) -> bool:
        is_syn = packet.flag(TCPFlags.SYN) and not packet.flag(TCPFlags.ACK)
        if not is_syn:
            return False
        if not state.syn_observed:
            # We joined midstream and now see a SYN: this must be a new
            # connection on the same tuple.
            return True
        if state.client_isn is not None and packet.seq != state.client_isn:
            return True
        return bool(state.saw_payload or state.closed or state.client_fin or state.server_fin)

    def _create(
        self,
        key: FlowKey,
        packet: ParsedPacket,
        ref: PacketReference,
        source: Endpoint,
        destination: Endpoint,
    ) -> _SessionState | None:
        if self.open_session_count >= self._config.max_concurrent_sessions:
            self._sink.add(
                WarningCode.LIMIT_CONCURRENT_SESSIONS,
                f"Refused a new connection: {self._config.max_concurrent_sessions} sessions "
                "are already open (max_concurrent_sessions). Its packets are not analysed.",
                severity=Severity.ERROR,
                packet_refs=(ref,),
                limit=self._config.max_concurrent_sessions,
            )
            return None
        if len(self._order) >= self._config.max_total_sessions:
            self._sink.add(
                WarningCode.LIMIT_TOTAL_SESSIONS,
                f"Refused a new connection: {self._config.max_total_sessions} sessions have "
                "already been recorded for this capture (max_total_sessions).",
                severity=Severity.ERROR,
                packet_refs=(ref,),
                limit=self._config.max_total_sessions,
            )
            return None

        client, server, status, basis = self._assign_roles(packet, source, destination)
        flow_id = flow_id_for(key)
        instance = self._instances.get(key, 0) + 1
        self._instances[key] = instance
        session_id = session_id_for(self._capture_id, flow_id, instance)

        flow = TCPFlow(
            flow_id=flow_id,
            address_family=packet.address_family,
            client=client,
            server=server,
            role_status=status,
            role_basis=basis,
        )
        state = _SessionState(
            session_id=session_id,
            capture_id=self._capture_id,
            flow=flow,
            instance=instance,
            config=self._config,
            sink=self._sink,
            global_budget=self._global_budget,
        )
        self._order.append(state)
        return state

    @staticmethod
    def _assign_roles(
        packet: ParsedPacket, source: Endpoint, destination: Endpoint
    ) -> tuple[Endpoint, Endpoint, EvidenceStatus, str]:
        if packet.flag(TCPFlags.SYN) and not packet.flag(TCPFlags.ACK):
            return source, destination, EvidenceStatus.OBSERVED, "TCP_SYN"
        if packet.flag(TCPFlags.SYN) and packet.flag(TCPFlags.ACK):
            return destination, source, EvidenceStatus.OBSERVED, "TCP_SYN_ACK"
        source_is_service = is_service_port(source.port)
        destination_is_service = is_service_port(destination.port)
        if source_is_service and not destination_is_service:
            return destination, source, EvidenceStatus.INFERRED, "WELL_KNOWN_PORT"
        if destination_is_service and not source_is_service:
            return source, destination, EvidenceStatus.INFERRED, "WELL_KNOWN_PORT"
        return source, destination, EvidenceStatus.INFERRED, "FIRST_PACKET_SENDER"

    def finalize(self) -> tuple[TCPSession, ...]:
        """Finalize every session, preserving first-seen order.

        Ordering by the packet number of each session's first packet keeps the
        report stable and diffable across runs.
        """
        self._completed.extend(self._active.values())
        self._active.clear()
        sessions = [state.finalize() for state in self._order]
        sessions.sort(key=lambda session: session.first_packet.packet_number)
        return tuple(sessions)

    def payload_runs(self) -> dict[tuple[str, Direction], list[tuple[int, bytes]]]:
        """Reconstructed bytes, keyed by ``(session_id, direction)``.

        This is the hand-off point for the M2 email-protocol layer and the M3
        TLS layer: each value is the list of contiguous ``(stream_offset,
        bytes)`` runs for that direction.  More than one run means the stream
        has holes, and a consumer must parse each run independently rather
        than concatenating across a gap.

        Payload bytes deliberately live here and not on the result models, so
        that serialising a report can never emit application data.
        """
        runs: dict[tuple[str, Direction], list[tuple[int, bytes]]] = {}
        for state in self._order:
            runs[state.session_id, Direction.CLIENT_TO_SERVER] = state.c2s.payload_runs()
            runs[state.session_id, Direction.SERVER_TO_CLIENT] = state.s2c.payload_runs()
        return runs

    @property
    def address_families_seen(self) -> set[AddressFamily]:  # pragma: no cover - diagnostics
        return {state.flow.address_family for state in self._order}
