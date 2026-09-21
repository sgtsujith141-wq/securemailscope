"""Shared test fixtures.

Captures are regenerated into a temporary directory for every test session, so
the suite never depends on a file that happens to be lying around in the
working tree.  Expectations come from the *committed* manifests in
``tests/fixtures/manifests``, and each test first asserts that the freshly
generated capture hashes to the value the manifest recorded.  A generator that
stops being deterministic therefore fails loudly instead of silently
invalidating every expectation.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from securemailscope.testing.fixtures import build_fixtures

MANIFEST_DIR = Path(__file__).parent / "fixtures" / "manifests"


@dataclass(frozen=True)
class Fixture:
    """A generated capture paired with its committed expectations.

    Fixtures whose bytes are not reproducible -- live OpenSSL handshakes and
    randomised ECDSA certificate signatures -- skip the capture-hash check and
    rely entirely on their semantic expectations.
    """

    name: str
    path: Path
    manifest: dict[str, Any]

    @property
    def expected_sessions(self) -> list[dict[str, Any]]:
        return self.manifest["expected_sessions"]

    @property
    def expected_warning_codes(self) -> set[str]:
        return set(self.manifest["expected_warning_codes"])

    @property
    def expected_tls(self) -> list[dict[str, Any]]:
        expected = self.manifest.get("expected_tls")
        assert expected is not None, f"{self.name} declares no TLS expectations"
        return expected

    @property
    def byte_reproducible(self) -> bool:
        return bool(self.manifest.get("byte_reproducible", True))


@pytest.fixture(scope="session")
def capture_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    directory = tmp_path_factory.mktemp("captures")
    for spec in build_fixtures():
        (directory / spec.filename).write_bytes(spec.data)
    return directory


@pytest.fixture(scope="session")
def manifests() -> dict[str, dict[str, Any]]:
    loaded = {}
    for path in sorted(MANIFEST_DIR.glob("*.json")):
        manifest = json.loads(path.read_text(encoding="utf-8"))
        loaded[manifest["name"]] = manifest
    assert loaded, f"no fixture manifests found in {MANIFEST_DIR}"
    return loaded


@pytest.fixture(scope="session")
def fixtures(capture_dir: Path, manifests: dict[str, dict[str, Any]]) -> dict[str, Fixture]:
    result: dict[str, Fixture] = {}
    for name, manifest in manifests.items():
        path = capture_dir / manifest["filename"]
        assert path.is_file(), f"fixture {name} was not generated"
        if manifest.get("byte_reproducible", True) and manifest.get("capture_sha256"):
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            assert digest == manifest["capture_sha256"], (
                f"fixture {name} is not reproducible: generated sha256 {digest} but the "
                f"committed manifest records {manifest['capture_sha256']}"
            )
        result[name] = Fixture(name=name, path=path, manifest=manifest)
    return result


@pytest.fixture(scope="session")
def trust_store_pem(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """The synthetic root, written out so chain verification can use it.

    Written at test time into a temporary directory: no certificate or key
    material is ever committed to the repository.
    """
    from securemailscope.testing.tls_fixtures import _ca

    directory = tmp_path_factory.mktemp("truststore")
    path = directory / "synthetic-root.pem"
    path.write_bytes(_ca().root_pem)
    return path


@pytest.fixture
def fixture(request: pytest.FixtureRequest, fixtures: dict[str, Fixture]) -> Fixture:
    """Parametrised access: ``@pytest.mark.parametrize("fixture", [...], indirect=True)``."""
    return fixtures[request.param]
