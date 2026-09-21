"""Explicitly configured trust anchors.

There is no default trust store.  Falling back to the operating system's
bundle would make a report say "chain verified" against a set of anchors the
report cannot name, on a machine that may differ from the analyst's.  When no
store is configured, chain verification is reported ``NOT_AVAILABLE``.

The anchor set is identified by a digest of its members' fingerprints rather
than by a filesystem path, so two reports can be compared without disclosing
where anyone keeps their files.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..models.certificates import TrustStoreInfo
from .parse import CRYPTOGRAPHY_AVAILABLE, load_pem_certificates

__all__ = ["LoadedTrustStore", "load_trust_store", "NO_TRUST_STORE"]

NO_TRUST_STORE = TrustStoreInfo(configured=False, anchor_count=0, source_kind="NONE")


@dataclass(frozen=True, slots=True)
class LoadedTrustStore:
    info: TrustStoreInfo
    anchors: tuple[Any, ...] = ()
    store: Any | None = None
    error: str | None = None

    @property
    def usable(self) -> bool:
        return self.store is not None and bool(self.anchors)


def _digest(anchors: list[Any]) -> str:
    from cryptography.hazmat.primitives import serialization

    fingerprints = sorted(
        hashlib.sha256(
            anchor.public_bytes(serialization.Encoding.DER)
        ).hexdigest()
        for anchor in anchors
    )
    return hashlib.sha256("".join(fingerprints).encode("ascii")).hexdigest()[:32]


def build_store(anchors: list[Any], *, source_kind: str) -> LoadedTrustStore:
    """Wrap already-decoded anchors into a verification store."""
    if not CRYPTOGRAPHY_AVAILABLE:  # pragma: no cover
        return LoadedTrustStore(
            info=NO_TRUST_STORE, error="the cryptography library is not installed"
        )
    if not anchors:
        return LoadedTrustStore(info=NO_TRUST_STORE, error="no trust anchors were supplied")
    from cryptography.x509.verification import Store

    info = TrustStoreInfo(
        configured=True,
        anchor_count=len(anchors),
        anchor_set_digest=_digest(anchors),
        source_kind=source_kind,
        policy="RFC5280_WEB_PKI",
    )
    return LoadedTrustStore(info=info, anchors=tuple(anchors), store=Store(anchors))


def load_trust_store(path: str | Path | None) -> LoadedTrustStore:
    """Load PEM trust anchors from ``path``. ``None`` means no store."""
    if path is None:
        return LoadedTrustStore(info=NO_TRUST_STORE)
    resolved = Path(path).expanduser()
    if not resolved.is_file():
        return LoadedTrustStore(
            info=NO_TRUST_STORE,
            error=f"the configured trust store is not a readable file: {resolved.name}",
        )
    try:
        anchors = load_pem_certificates(resolved.read_bytes())
    except Exception as error:
        return LoadedTrustStore(
            info=NO_TRUST_STORE,
            error=f"the configured trust store could not be decoded: {type(error).__name__}",
        )
    return build_store(anchors, source_kind="EXPLICIT_FILE")
