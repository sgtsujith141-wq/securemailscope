"""Model persistence with integrity checks (M6).

Loading a model is deserialising code. joblib and pickle will execute whatever
a crafted artifact tells them to, so this module never loads an arbitrary file:

* artifacts are read **only** from a controlled directory, resolved and checked
  to be inside it, so a path in a report or a config cannot point elsewhere;
* every artifact is accompanied by a committed manifest recording its SHA-256,
  and the digest is verified **before** the file is opened for deserialisation;
* the feature schema version and model version in the manifest must match what
  this build supports, and a mismatch is a refusal rather than a best effort;
* nothing is ever downloaded. There is no registry service, no URL and no
  network access at any point.

A rejected model is reported as ``MODEL_REJECTED`` with a reason. The forensic
analyzer continues regardless, because it does not depend on any of this.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

from .features import FEATURE_SCHEMA_VERSION

__all__ = [
    "MODEL_DIRECTORY",
    "MODEL_FORMAT_VERSION",
    "SUPPORTED_MODEL_VERSIONS",
    "ModelRejected",
    "ArtifactManifest",
    "default_model_directory",
    "save_model",
    "load_model",
    "read_manifest",
]

#: The only directory models are read from. Committed alongside the code so
#: the artifact and the build that produced it travel together.
MODEL_DIRECTORY: Final = Path(__file__).resolve().parent / "artifacts"

#: The artifact layout. Independent of the model's own version: a change here
#: means old artifacts cannot be read at all.
MODEL_FORMAT_VERSION: Final = "smsmodel/1"

#: Model versions this build will load. An artifact outside this set is
#: rejected rather than loaded and hoped for.
SUPPORTED_MODEL_VERSIONS: Final[frozenset[str]] = frozenset({"1.0.0"})


class ModelRejected(Exception):
    """Raised when an artifact cannot be trusted or cannot be used.

    Deliberately an exception rather than a ``None`` return: a caller that
    forgets to check a return value would silently run without a model, and
    the difference between "no model installed" and "the model was tampered
    with" must never be lost.
    """


@dataclass(frozen=True)
class ArtifactManifest:
    """The committed record describing one artifact."""

    model_id: str
    model_version: str
    format_version: str
    algorithm: str
    feature_schema_version: str
    dataset_id: str
    dataset_version: str
    trained_at: str
    training_sample_count: int
    reference_population: str
    hyperparameters: dict[str, Any]
    artifact_filename: str
    artifact_sha256: str
    library_versions: dict[str, str]
    evaluation_report: str
    decision_threshold: float | None = None
    classes: list[str] | None = None
    limitations: list[str] | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ArtifactManifest:
        known = {field: data.get(field) for field in cls.__dataclass_fields__}
        return cls(**known)  # type: ignore[arg-type]


def default_model_directory() -> Path:
    return MODEL_DIRECTORY


def _digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


def library_versions() -> dict[str, str]:
    """Record what produced an artifact, so a reader can reproduce it."""
    import platform
    import sys

    versions = {"python": sys.version.split()[0], "platform": platform.platform()}
    for name in ("sklearn", "numpy", "scipy", "joblib"):
        try:
            module = __import__(name)
        except ImportError:  # pragma: no cover - all are installed with the extra
            continue
        versions[name] = getattr(module, "__version__", "unknown")
    return versions


def save_model(
    payload: Any,
    *,
    model_id: str,
    model_version: str,
    algorithm: str,
    dataset_id: str,
    dataset_version: str,
    training_sample_count: int,
    reference_population: str,
    hyperparameters: dict[str, Any],
    evaluation_report: str,
    directory: Path | None = None,
    decision_threshold: float | None = None,
    classes: list[str] | None = None,
    limitations: list[str] | None = None,
) -> ArtifactManifest:
    """Write an artifact and its manifest, digest last so it always matches."""
    import joblib

    target = directory or MODEL_DIRECTORY
    target.mkdir(parents=True, exist_ok=True)
    artifact_name = f"{model_id}-{model_version}.joblib"
    artifact_path = target / artifact_name
    joblib.dump(payload, artifact_path, compress=3)

    manifest = ArtifactManifest(
        model_id=model_id,
        model_version=model_version,
        format_version=MODEL_FORMAT_VERSION,
        algorithm=algorithm,
        feature_schema_version=FEATURE_SCHEMA_VERSION,
        dataset_id=dataset_id,
        dataset_version=dataset_version,
        trained_at=datetime.now(UTC).isoformat(timespec="seconds"),
        training_sample_count=training_sample_count,
        reference_population=reference_population,
        hyperparameters=hyperparameters,
        artifact_filename=artifact_name,
        artifact_sha256=_digest(artifact_path),
        library_versions=library_versions(),
        evaluation_report=evaluation_report,
        decision_threshold=decision_threshold,
        classes=classes,
        limitations=limitations or [],
    )
    manifest_path = target / f"{model_id}-{model_version}.manifest.json"
    manifest_path.write_text(
        json.dumps(manifest.__dict__, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return manifest


def read_manifest(path: Path) -> ArtifactManifest:
    return ArtifactManifest.from_dict(json.loads(path.read_text(encoding="utf-8")))


def load_model(
    model_id: str,
    *,
    directory: Path | None = None,
) -> tuple[Any, ArtifactManifest]:
    """Load one artifact, refusing anything that cannot be trusted.

    Every check below is a refusal, not a warning, and each happens before the
    next: the path is confined, the manifest is read, the digest is verified,
    the versions are checked, and only then is the file deserialised.
    """
    root = (directory or MODEL_DIRECTORY).resolve()
    manifests = sorted(root.glob(f"{model_id}-*.manifest.json"))
    if not manifests:
        raise ModelRejected(
            f"no manifest for model {model_id!r} in {root}. No model is installed; "
            "the forensic analysis is unaffected."
        )
    manifest = read_manifest(manifests[-1])

    if manifest.format_version != MODEL_FORMAT_VERSION:
        raise ModelRejected(
            f"artifact format {manifest.format_version!r} is not "
            f"{MODEL_FORMAT_VERSION!r}; refusing to load it."
        )
    if manifest.model_version not in SUPPORTED_MODEL_VERSIONS:
        raise ModelRejected(
            f"model version {manifest.model_version!r} is not supported by this "
            f"build (supported: {sorted(SUPPORTED_MODEL_VERSIONS)}). Refusing "
            "rather than loading a model whose behaviour is unknown."
        )
    if manifest.feature_schema_version != FEATURE_SCHEMA_VERSION:
        raise ModelRejected(
            f"model expects feature schema {manifest.feature_schema_version!r} "
            f"but this build produces {FEATURE_SCHEMA_VERSION!r}. The columns "
            "would not line up, so the model is refused."
        )

    artifact_path = (root / manifest.artifact_filename).resolve()
    # A manifest is data. It must not be able to point the loader at a file
    # outside the controlled directory.
    if root not in artifact_path.parents:
        raise ModelRejected(
            f"artifact path {manifest.artifact_filename!r} resolves outside the "
            f"model directory; refusing to load it."
        )
    if not artifact_path.is_file():
        raise ModelRejected(f"artifact {artifact_path.name} is missing.")

    actual = _digest(artifact_path)
    if actual != manifest.artifact_sha256:
        raise ModelRejected(
            f"artifact digest mismatch for {artifact_path.name}: manifest records "
            f"{manifest.artifact_sha256[:16]}..., file hashes to {actual[:16]}.... "
            "The artifact has been modified since it was recorded and will not "
            "be deserialised."
        )

    import joblib

    return joblib.load(artifact_path), manifest
