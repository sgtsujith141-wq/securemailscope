"""Reproducible synthetic dataset construction (M6).

Every sample in this dataset is a **real capture, analysed by the real
pipeline**. Nothing is fabricated at the feature level: the generator writes
pcap bytes, the M1-M5 engine reconstructs the session and the feature extractor
reads the resulting observations. A bug in the analyzer therefore shows up in
the dataset rather than being papered over by a shortcut.

## The three kinds of truth, kept apart

The directive is emphatic that these must not be conflated, and the design
turns on keeping them separate:

**Forensic ground truth** -- what the generated capture actually contains. Held
in :class:`GeneratedSession` and used only to check the analyzer read the
capture correctly.

**Security policy label** -- how the M4 policy evaluates the observed session.
Produced by the assessment engine. It is *never* used as an ML target, because
a model trained on it would only learn to imitate a deterministic rule engine
we already have.

**ML evaluation label** -- defined here, independently, and deliberately
*latent*: it describes the **whole server configuration**, of which a single
captured session reveals only a part.

## Why the label is latent

A server has a complete configuration: a minimum protocol version, a full list
of suites it is willing to negotiate, a certificate practice. A capture shows
one negotiation with one client. A server that still permits RC4 will not
reveal that to a modern client that never offers it -- the session looks
perfect, and the server is not.

So the classification target is the **server's posture class**, assigned by the
documented rubric in :func:`posture_class` over the server's *full* generated
configuration, and the features come only from what the capture observed. The
model is therefore inferring a latent property from partial evidence, with
irreducible uncertainty. That is a real learning problem, and it is a different
problem from the one M4 solves.

It also means perfect accuracy is not achievable and would be a red flag: some
sessions genuinely do not contain enough evidence to distinguish a careful
server from a careless one.

## Provenance and authorisation

All data is generated locally by this module from fixed seeds. No capture is
downloaded, no real traffic is used, no server is contacted and no third-party
dataset is involved, so no licensing or authorisation question arises. The
synthetic certificate authority mints throwaway keys in memory; none is
committed.
"""

from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final, Literal

from ..testing.certs import CAPTURE_EPOCH, IssuedCertificate, KeyKind, SyntheticCA
from ..testing.dialogue import Dialogue
from ..testing.tls_messages import (
    CONTENT_HANDSHAKE,
    TLS10,
    TLS11,
    TLS12,
    TLS13,
    certificate_message,
    client_hello,
    record,
    server_hello,
    server_hello_done,
)
from ..testing.writers import write_pcap

__all__ = [
    "DATASET_ID",
    "DATASET_VERSION",
    "CONFIGURATION_FAMILIES",
    "POSTURE_CLASSES",
    "ServerProfile",
    "ClientProfile",
    "GeneratedSession",
    "posture_class",
    "build_population",
    "generate_sessions",
    "dataset_fingerprint",
    "capture_size_profile",
]

DATASET_ID: Final = "securemailscope-synthetic-tls"
DATASET_VERSION: Final = "1.0.0"

#: Seeds are part of the dataset definition, not an implementation detail.
POPULATION_SEED: Final = 20260921
SESSION_SEED: Final = 815

PostureClass = Literal["LOW", "MODERATE", "HIGH", "CRITICAL"]
POSTURE_CLASSES: Final[tuple[str, ...]] = ("LOW", "MODERATE", "HIGH", "CRITICAL")

# ---------------------------------------------------------------------------
# Suite vocabulary
#
# Grouped by the property that matters to the rubric, so the rubric can be read
# without a lookup table.
# ---------------------------------------------------------------------------
AEAD_SUITES: Final = {
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
}
CBC_EPHEMERAL_SUITES: Final = {
    0xC013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    0xC014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
}
STATIC_RSA_SUITES: Final = {
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
}
SWEET32_SUITES: Final = {0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA"}
BROKEN_SUITES: Final = {
    0x0005: "TLS_RSA_WITH_RC4_128_SHA",
    0x003B: "TLS_RSA_WITH_NULL_SHA256",
}

#: Configuration families. Each is a *population*, not a label: several
#: families can produce the same posture class, and one family can produce
#: several, which is what stops the family name being a proxy for the target.
CONFIGURATION_FAMILIES: Final[tuple[str, ...]] = (
    "modern_aead",
    "intermediate",
    "legacy_compatible",
    "mixed_migration",
    "outdated",
    "hardened_uncommon",
    "anomalous_combination",
)

#: Families whose sessions form the anomaly detector's reference population --
#: what "normal" means for this dataset, stated explicitly because
#: "unusual" has no meaning without it.
REFERENCE_FAMILIES: Final[frozenset[str]] = frozenset(
    {"modern_aead", "intermediate", "legacy_compatible", "mixed_migration", "outdated"}
)

#: Rare but entirely legitimate. Held out as a **negative control**: a detector
#: that flags these is reporting unfamiliarity, not risk, and the evaluation
#: reports that honestly rather than hiding it.
NEGATIVE_CONTROL_FAMILY: Final = "hardened_uncommon"

#: Combinations that do not occur in the reference population at all. These are
#: the injected anomalies, declared here before any model is trained.
ANOMALY_FAMILY: Final = "anomalous_combination"


@dataclass(frozen=True)
class ServerProfile:
    """A server's **complete** configuration -- most of it never observable.

    A capture reveals the one suite that was negotiated. It does not reveal
    what else the server would have accepted, which is precisely the gap the
    classification task asks a model to reason across.
    """

    server_id: str
    family: str
    minimum_version: int
    #: Every suite the server is willing to negotiate, in preference order.
    supported_suites: tuple[int, ...]
    cert_key_kind: str
    cert_key_bits: int | None
    cert_signature_hash: str
    cert_lifetime_days: int
    #: True when the operator left a legacy listener enabled elsewhere. Not
    #: observable in a single session, and deliberately part of the rubric.
    legacy_listener_enabled: bool
    ip: str
    port: int


@dataclass(frozen=True)
class ClientProfile:
    """What one client offers. Varies independently of the server."""

    client_id: str
    offered_versions: tuple[int, ...]
    offered_suites: tuple[int, ...]
    sends_sni: bool


@dataclass(frozen=True)
class GeneratedSession:
    """One generated capture, with the forensic truth of what is in it."""

    sample_id: str
    server: ServerProfile
    client: ClientProfile
    family: str
    posture: str
    #: Forensic ground truth: what the bytes actually contain.
    negotiated_version: int | None
    negotiated_suite: int | None
    certificate_present: bool
    capture_bytes: bytes = field(repr=False)
    #: True when this sample was drawn from the injected-anomaly family.
    injected_anomaly: bool = False
    negative_control: bool = False


def posture_class(server: ServerProfile) -> PostureClass:
    """Assign a posture class from the server's **whole** configuration.

    This is the independently defined ML evaluation label. It is a documented
    rubric over properties a single capture mostly cannot see, and it does not
    call the M4 engine, read an M4 score or consult an M4 severity.

    The rubric is informed by RFC 9325 and the widely used Mozilla TLS
    configuration tiers, but it is a **project-defined ordering**, not a
    reproduction of either, and it is applied to the server rather than to a
    session. The criteria, in order of precedence:

    ``CRITICAL``
        The server will negotiate a suite offering no confidentiality or a
        broken cipher (NULL, RC4) with *some* client, whatever it happened to
        negotiate in the captured session.

    ``HIGH``
        It permits a 64-bit block cipher or static RSA key exchange, or accepts
        a protocol version below TLS 1.2, or presents an RSA key under 2048
        bits -- any of which removes forward secrecy or a protocol guarantee
        for at least some clients.

    ``MODERATE``
        Modern floor and no prohibited suite, but it still permits CBC
        construction, issues certificates lasting longer than 825 days, or
        keeps a legacy listener enabled elsewhere on the host.

    ``LOW``
        TLS 1.2 or better, AEAD suites only, a strong key, a short certificate
        lifetime and no legacy listener.
    """
    supported = set(server.supported_suites)
    if supported & set(BROKEN_SUITES):
        return "CRITICAL"
    if (
        supported & set(SWEET32_SUITES)
        or supported & set(STATIC_RSA_SUITES)
        or server.minimum_version < TLS12
        or (server.cert_key_kind == "rsa" and (server.cert_key_bits or 0) < 2048)
    ):
        return "HIGH"
    if (
        supported & set(CBC_EPHEMERAL_SUITES)
        or server.cert_lifetime_days > 825
        or server.legacy_listener_enabled
    ):
        return "MODERATE"
    return "LOW"


def _family_server(
    family: str, index: int, rng: random.Random
) -> ServerProfile:
    """Draw one server from a family's population.

    Each family deliberately spans more than one posture class -- an
    ``intermediate`` server may or may not have a legacy listener, an
    ``outdated`` one may or may not still permit RC4 -- so the family name
    cannot stand in for the label.
    """
    aead = list(AEAD_SUITES)
    tls13 = [0x1301, 0x1302, 0x1303]
    ip = f"198.51.100.{10 + (index % 200)}"
    port = rng.choice((993, 995, 465, 587, 25))
    common: dict[str, Any] = {
        "server_id": f"srv-{family}-{index:04d}",
        "family": family,
        "ip": ip,
        "port": port,
    }

    if family == "modern_aead":
        return ServerProfile(
            **common,
            minimum_version=TLS13 if rng.random() < 0.6 else TLS12,
            supported_suites=tuple(rng.sample(tls13, k=rng.randint(2, 3))),
            cert_key_kind=rng.choice(("ec256", "ec256", "ed25519")),
            cert_key_bits=256,
            cert_signature_hash="sha256",
            cert_lifetime_days=rng.choice((90, 180, 365)),
            legacy_listener_enabled=rng.random() < 0.10,
        )
    if family == "intermediate":
        return ServerProfile(
            **common,
            minimum_version=TLS12,
            supported_suites=tuple(rng.sample(aead, k=rng.randint(3, 5))),
            cert_key_kind=rng.choice(("ec256", "rsa2048", "rsa2048")),
            cert_key_bits=rng.choice((256, 2048)),
            cert_signature_hash="sha256",
            cert_lifetime_days=rng.choice((365, 398, 730, 1095)),
            legacy_listener_enabled=rng.random() < 0.25,
        )
    if family == "legacy_compatible":
        return ServerProfile(
            **common,
            minimum_version=TLS12,
            supported_suites=tuple(
                rng.sample(aead, k=2) + rng.sample(list(CBC_EPHEMERAL_SUITES), k=1)
            ),
            cert_key_kind="rsa2048",
            cert_key_bits=2048,
            cert_signature_hash="sha256",
            cert_lifetime_days=rng.choice((365, 730, 1095)),
            legacy_listener_enabled=rng.random() < 0.4,
        )
    if family == "mixed_migration":
        # Mid-migration: modern suites are present, older ones not yet removed.
        return ServerProfile(
            **common,
            minimum_version=rng.choice((TLS10, TLS11, TLS12)),
            supported_suites=tuple(
                rng.sample(aead, k=2) + rng.sample(list(STATIC_RSA_SUITES), k=1)
            ),
            cert_key_kind=rng.choice(("rsa2048", "ec256")),
            cert_key_bits=rng.choice((2048, 256)),
            cert_signature_hash="sha256",
            cert_lifetime_days=rng.choice((730, 1095)),
            legacy_listener_enabled=rng.random() < 0.6,
        )
    if family == "outdated":
        pool = list(STATIC_RSA_SUITES) + list(SWEET32_SUITES) + list(CBC_EPHEMERAL_SUITES)
        suites = rng.sample(pool, k=rng.randint(2, 3))
        if rng.random() < 0.35:
            suites.append(rng.choice(list(BROKEN_SUITES)))
        return ServerProfile(
            **common,
            minimum_version=rng.choice((TLS10, TLS10, TLS11)),
            supported_suites=tuple(suites),
            cert_key_kind=rng.choice(("rsa1024", "rsa2048")),
            cert_key_bits=rng.choice((1024, 2048)),
            cert_signature_hash=rng.choice(("sha256", "sha1")),
            cert_lifetime_days=rng.choice((1095, 1825)),
            legacy_listener_enabled=True,
        )
    if family == "hardened_uncommon":
        # Strong, but an unusual shape: ChaCha20-only, Ed25519, very short
        # lifetimes. A detector that flags these is reporting unfamiliarity.
        return ServerProfile(
            **common,
            minimum_version=TLS13,
            supported_suites=(0x1303,),
            cert_key_kind="ed25519",
            cert_key_bits=None,
            cert_signature_hash="ed25519",
            cert_lifetime_days=rng.choice((7, 14, 30)),
            legacy_listener_enabled=False,
        )
    # anomalous_combination: pairings that do not occur in the reference
    # population -- a modern floor beside a weak certificate, or a strong
    # certificate in front of a broken suite.
    # Each variant pairs properties that never co-occur in the reference
    # population, and pairs them in a way a *single session* can reveal --
    # otherwise the detector would be asked to see something the capture does
    # not contain.
    variant = rng.randint(0, 2)
    if variant == 0:
        # A modern AEAD suite in front of a 1024-bit RSA key signed with SHA-1.
        return ServerProfile(
            **common,
            minimum_version=TLS12,
            supported_suites=(0xC02F, 0x009C),
            cert_key_kind="rsa1024",
            cert_key_bits=1024,
            cert_signature_hash="sha1",
            cert_lifetime_days=3650,
            legacy_listener_enabled=True,
        )
    if variant == 1:
        # ChaCha20 negotiated over TLS 1.0, with a decade-long certificate.
        return ServerProfile(
            **common,
            minimum_version=TLS10,
            supported_suites=(0xCCA8, 0x0005),
            cert_key_kind="ec256",
            cert_key_bits=256,
            cert_signature_hash="sha256",
            cert_lifetime_days=7300,
            legacy_listener_enabled=True,
        )
    # 3DES in front of a fifteen-year 1024-bit certificate.
    return ServerProfile(
        **common,
        minimum_version=TLS10,
        supported_suites=(0x000A, 0x002F),
        cert_key_kind="rsa1024",
        cert_key_bits=1024,
        cert_signature_hash="sha1",
        cert_lifetime_days=5475,
        legacy_listener_enabled=True,
    )


#: How many servers each family contributes. Chosen so the reference
#: population dominates -- anomalies are rare by construction, as they are in
#: reality -- while leaving enough of each class to evaluate.
FAMILY_SIZES: Final[dict[str, int]] = {
    "modern_aead": 26,
    "intermediate": 30,
    "legacy_compatible": 24,
    "mixed_migration": 22,
    "outdated": 26,
    "hardened_uncommon": 12,
    "anomalous_combination": 12,
}


def build_population(seed: int = POPULATION_SEED) -> list[ServerProfile]:
    """The full server population, reproducible from one seed."""
    # Deterministic reproducibility is the requirement here, not
    # unpredictability: the same seed must always yield the same dataset.
    rng = random.Random(seed)  # noqa: S311 - reproducibility, not cryptography
    servers: list[ServerProfile] = []
    for family in CONFIGURATION_FAMILIES:
        for index in range(FAMILY_SIZES[family]):
            servers.append(_family_server(family, index, rng))
    return servers


_CLIENT_POOL: Final[tuple[ClientProfile, ...]] = (
    ClientProfile(
        "cli-modern",
        (TLS13, TLS12),
        (0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC030, 0xCCA8),
        True,
    ),
    ClientProfile(
        "cli-standard", (TLS12,), (0xC02B, 0xC02F, 0xC030, 0xC013, 0xC014), True
    ),
    ClientProfile(
        "cli-compatible",
        (TLS12, TLS11, TLS10),
        (0xC02F, 0xC013, 0x002F, 0x0035, 0x009C, 0x000A),
        True,
    ),
    ClientProfile(
        "cli-ancient", (TLS10,), (0x002F, 0x0035, 0x000A, 0x0005), False
    ),
    ClientProfile("cli-narrow", (TLS12,), (0x009C, 0x002F), True),
)


def _negotiate(
    server: ServerProfile, client: ClientProfile
) -> tuple[int | None, int | None]:
    """Pick the version and suite the pair would agree on.

    Ordinary TLS selection: the highest mutually supported version at or above
    the server's floor, then the server's first preference among the suites the
    client offered. Returns ``(None, None)`` when there is no overlap, which
    yields a capture with a ClientHello and no answer.
    """
    versions = [v for v in client.offered_versions if v >= server.minimum_version]
    if not versions:
        return None, None
    version = max(versions)
    if version == TLS13:
        candidates = [s for s in server.supported_suites if s in (0x1301, 0x1302, 0x1303)]
    else:
        candidates = [
            s
            for s in server.supported_suites
            if s not in (0x1301, 0x1302, 0x1303) and s in client.offered_suites
        ]
    if version == TLS13:
        candidates = [s for s in candidates if s in client.offered_suites]
    if not candidates:
        return None, None
    return version, candidates[0]


def generate_sessions(
    *,
    population_seed: int = POPULATION_SEED,
    session_seed: int = SESSION_SEED,
    sessions_per_server: int = 4,
) -> list[GeneratedSession]:
    """Generate the full dataset: real captures with their latent labels."""
    authority = SyntheticCA()
    servers = build_population(population_seed)
    rng = random.Random(session_seed)  # noqa: S311 - reproducibility, not cryptography
    out: list[GeneratedSession] = []
    serial = 10_000

    for server in servers:
        posture = posture_class(server)
        leaf = authority.issue(
            f"{server.server_id}.example.invalid",
            sans=[f"{server.server_id}.example.invalid"],
            key_kind=_key_kind(server.cert_key_kind),
            serial=serial,
            not_before_days=-30,
            not_after_days=server.cert_lifetime_days - 30,
        )
        serial += 1
        compatible = [
            candidate
            for candidate in _CLIENT_POOL
            if _negotiate(server, candidate)[0] is not None
        ]
        for order in range(sessions_per_server):
            # Mostly clients that can actually talk to this server, as in real
            # traffic; a minority that cannot, so the dataset contains genuine
            # "no shared configuration" sessions rather than only clean ones.
            if compatible and rng.random() < 0.85:
                client = rng.choice(compatible)
            else:
                client = rng.choice(_CLIENT_POOL)
            version, suite = _negotiate(server, client)
            # A minority of sessions are cut short before the server's answer,
            # so the dataset contains genuinely incomplete evidence rather than
            # only clean handshakes.
            truncated = rng.random() < 0.08
            if truncated:
                version, suite = None, None
            data = _capture_bytes(
                server, client, version, suite, leaf, truncated=truncated, order=order
            )
            certificate_present = (
                version is not None and version != TLS13 and not truncated
            )
            sample_id = "smp-" + hashlib.sha256(
                f"{server.server_id}|{client.client_id}|{order}".encode()
            ).hexdigest()[:12]
            out.append(
                GeneratedSession(
                    sample_id=sample_id,
                    server=server,
                    client=client,
                    family=server.family,
                    posture=posture,
                    negotiated_version=version,
                    negotiated_suite=suite,
                    certificate_present=certificate_present,
                    capture_bytes=data,
                    injected_anomaly=server.family == ANOMALY_FAMILY,
                    negative_control=server.family == NEGATIVE_CONTROL_FAMILY,
                )
            )
    return out


def _key_kind(kind: str) -> KeyKind:
    """Map a profile's key description to the authority's key kind.

    Identity, deliberately: collapsing ``rsa1024`` onto ``rsa2048`` would make
    a weak key unobservable in the capture while the rubric still counted it,
    which would put an unlearnable component into the label.
    """
    mapping: dict[str, KeyKind] = {
        "ec256": "ec256",
        "rsa2048": "rsa2048",
        "rsa1024": "rsa1024",
        "ed25519": "ed25519",
    }
    return mapping[kind]


def _capture_bytes(
    server: ServerProfile,
    client: ClientProfile,
    version: int | None,
    suite: int | None,
    leaf: IssuedCertificate,
    *,
    truncated: bool,
    order: int,
) -> bytes:
    """Write one session's pcap bytes."""
    hello_version = TLS12 if TLS13 in client.offered_versions else max(
        client.offered_versions
    )
    start = int(CAPTURE_EPOCH.timestamp()) * 1_000_000_000 + order * 60_000_000_000
    dialogue = Dialogue(
        server_ip=server.ip,
        server_port=server.port,
        client_port=49152 + order,
        handshake=True,
        start_ns=start,
    )
    dialogue.send_client(
        record(
            CONTENT_HANDSHAKE,
            client_hello(
                legacy_version=hello_version,
                cipher_suites=list(client.offered_suites),
                server_name=(
                    f"{server.server_id}.example.invalid" if client.sends_sni else None
                ),
                supported_versions=(
                    list(client.offered_versions)
                    if TLS13 in client.offered_versions
                    else None
                ),
                key_share_groups=[0x001D] if TLS13 in client.offered_versions else None,
            ),
            version=hello_version,
        )
    )
    if truncated or version is None or suite is None:
        return write_pcap(dialogue.packets)

    if version == TLS13:
        flight = server_hello(
            legacy_version=TLS12,
            cipher_suite=suite,
            supported_version=TLS13,
            key_share_group=0x001D,
        )
    else:
        flight = (
            server_hello(legacy_version=version, cipher_suite=suite)
            + certificate_message([leaf.der])
            + server_hello_done()
        )
    dialogue.send_server(record(CONTENT_HANDSHAKE, flight, version=hello_version))
    return write_pcap(dialogue.packets)


def dataset_fingerprint(sessions: list[GeneratedSession]) -> str:
    """A digest over the dataset's **content**, so reproducibility is checkable.

    Deliberately not a digest of the capture bytes. The synthetic authority
    mints a fresh key for every certificate, and ECDSA signatures vary in DER
    length between runs, so two runs from the same seeds produce captures that
    differ by a byte or two inside the certificate while describing exactly the
    same sessions.

    What must be reproducible is the dataset: the same servers, the same
    clients, the same negotiations and the same labels. That is what this
    digest covers, and :func:`capture_size_profile` records the byte-level
    variation rather than hiding it.
    """
    digest = hashlib.sha256()
    for session in sorted(sessions, key=lambda item: item.sample_id):
        digest.update(
            "|".join(
                (
                    session.sample_id,
                    session.server.server_id,
                    session.client.client_id,
                    session.family,
                    session.posture,
                    str(session.negotiated_version),
                    str(session.negotiated_suite),
                    str(session.certificate_present),
                )
            ).encode()
        )
    return digest.hexdigest()[:16]


def capture_size_profile(sessions: list[GeneratedSession]) -> dict[str, int]:
    """Byte-level statistics, so the non-reproducible part is stated, not hidden."""
    sizes = [len(session.capture_bytes) for session in sessions]
    return {
        "captures": len(sizes),
        "total_bytes": sum(sizes),
        "min_bytes": min(sizes) if sizes else 0,
        "max_bytes": max(sizes) if sizes else 0,
    }


def write_captures(sessions: list[GeneratedSession], directory: Path) -> dict[str, Path]:
    """Write each sample's capture so the real pipeline can read it."""
    directory.mkdir(parents=True, exist_ok=True)
    paths: dict[str, Path] = {}
    for session in sessions:
        path = directory / f"{session.sample_id}.pcap"
        path.write_bytes(session.capture_bytes)
        paths[session.sample_id] = path
    return paths
