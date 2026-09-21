"""M8: the dependency and supply-chain audit, enforced rather than described.

Two failure modes this guards against.

*Undeclared dependencies.* A package that happens to be installed in a
developer's environment works there and fails on a clean install. The only
reliable way to catch it is to compare what the source imports against what the
project declares, which is what the first test does.

*Layering drift.* The forensic engine deliberately depends on ``scapy``,
``pydantic`` and ``cryptography`` and nothing else, so it stays installable and
testable without the web stack or scikit-learn. An engine module that quietly
imports FastAPI would break that without any test noticing.
"""

from __future__ import annotations

import ast
import sys
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "securemailscope"

#: Distribution name -> the module name it provides, where they differ.
_MODULE_NAMES = {
    "scikit-learn": "sklearn",
    "python-multipart": "multipart",
    "pypdfium2": "pypdfium2",
}

#: Imported inside a function body for optional features, and exercised by
#: tests that skip when the package is absent.
_OPTIONAL_AT_RUNTIME = {"sklearn", "numpy", "scipy", "joblib"}


def _declared() -> dict[str, set[str]]:
    """Every declared dependency, as module names, grouped by extra."""
    data = tomllib.loads((ROOT / "pyproject.toml").read_text())
    project = data["project"]
    groups = {"(required)": project["dependencies"]}
    groups.update(project.get("optional-dependencies", {}))

    resolved: dict[str, set[str]] = {}
    for group, specifiers in groups.items():
        modules = set()
        for specifier in specifiers:
            name = specifier.split("==")[0].split(">=")[0].split("[")[0].strip()
            modules.add(_MODULE_NAMES.get(name, name.replace("-", "_").lower()))
        resolved[group] = modules
    return resolved


def _imported(paths: list[Path]) -> dict[str, list[Path]]:
    """Top-level module names imported by the given files."""
    found: dict[str, list[Path]] = {}
    for path in paths:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [alias.name.split(".")[0] for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                if node.level:  # relative import: internal
                    continue
                names = [(node.module or "").split(".")[0]]
            else:
                continue
            for name in names:
                if name and name not in sys.stdlib_module_names:
                    found.setdefault(name, []).append(path)
    return found


def test_every_third_party_import_is_declared() -> None:
    """Nothing may rely on a package that merely happens to be installed."""
    declared = set().union(*_declared().values())
    declared |= {"securemailscope", "pytest"}

    sources = sorted(SRC.rglob("*.py"))
    sources += sorted((ROOT / "tests").rglob("*.py"))
    sources += sorted((ROOT / "scripts").glob("*.py"))
    imported = _imported(sources)

    undeclared = {
        name: sorted(str(p.relative_to(ROOT)) for p in paths)
        for name, paths in imported.items()
        if name not in declared
    }
    assert not undeclared, (
        "these modules are imported but not declared in pyproject.toml:\n"
        + "\n".join(f"  {name}: {', '.join(files)}" for name, files in undeclared.items())
    )


def test_every_declared_dependency_is_pinned_exactly() -> None:
    """A range means two developers can resolve to different code."""
    data = tomllib.loads((ROOT / "pyproject.toml").read_text())
    project = data["project"]
    groups = {"(required)": project["dependencies"]}
    groups.update(project.get("optional-dependencies", {}))

    unpinned = [
        f"{group}: {spec}"
        for group, specs in groups.items()
        for spec in specs
        if "==" not in spec
    ]
    assert not unpinned, "unpinned dependencies:\n" + "\n".join(unpinned)


def test_every_declared_dependency_is_actually_used() -> None:
    """A declared package nobody imports is an unnecessary dependency."""
    sources = sorted(SRC.rglob("*.py"))
    sources += sorted((ROOT / "tests").rglob("*.py"))
    sources += sorted((ROOT / "scripts").glob("*.py"))
    imported = set(_imported(sources))
    # Tools invoked as commands rather than imported.
    invoked = {"ruff", "mypy", "uvicorn", "pytest", "hypothesis"}
    # Required, but reached through another package rather than by an import
    # here: pypdfium2 rasterises pages for pypdf; httpx is the transport
    # fastapi.testclient.TestClient is built on; python-multipart is what
    # FastAPI uses to parse the multipart body behind ``UploadFile``. Removing
    # any of the three breaks the project, so each stays declared.
    indirect = {"pypdfium2", "httpx", "multipart"}

    unused = {
        module
        for group, modules in _declared().items()
        for module in modules
        if module not in imported and module not in invoked and module not in indirect
    }
    assert not unused, f"declared but never imported: {sorted(unused)}"


ENGINE_ALLOWED = {"scapy", "pydantic", "cryptography", "securemailscope"}

#: Directories that are deliberately outside the engine's dependency floor.
NON_ENGINE = {"backend", "ml", "reporting", "benchmarks"}


def test_the_forensic_engine_does_not_import_the_web_or_ml_stack() -> None:
    """The layering rule from ADR 0001, checked rather than trusted."""
    engine_files = [
        path
        for path in sorted(SRC.rglob("*.py"))
        if not any(part in NON_ENGINE for part in path.relative_to(SRC).parts)
    ]
    assert engine_files, "no engine files were found; the path filter is wrong"

    violations = {
        name: sorted(str(p.relative_to(ROOT)) for p in paths)
        for name, paths in _imported(engine_files).items()
        if name not in ENGINE_ALLOWED and name not in _OPTIONAL_AT_RUNTIME
    }
    assert not violations, (
        "the forensic engine imports outside its dependency floor:\n"
        + "\n".join(f"  {name}: {', '.join(files)}" for name, files in violations.items())
    )


def test_the_engine_imports_with_only_its_required_dependencies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Importing the engine must not pull in FastAPI, SQLAlchemy or sklearn."""
    import subprocess

    script = (
        "import sys;"
        "import securemailscope.pipeline;"
        "banned=[m for m in ('fastapi','sqlalchemy','sklearn','uvicorn','reportlab',"
        "'jinja2') if m in sys.modules];"
        "print(','.join(banned))"
    )
    result = subprocess.run(  # noqa: S603 - fixed argv, this interpreter only
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        cwd=ROOT,
        check=True,
    )
    assert result.stdout.strip() == "", (
        f"importing the engine loaded: {result.stdout.strip()}"
    )


def test_the_lock_file_matches_what_is_declared() -> None:
    """The lock file records the exact resolved environment, including transitives."""
    lock = ROOT / "requirements-lock.txt"
    assert lock.is_file(), "requirements-lock.txt is missing; run make lock"

    locked = {}
    for line in lock.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        assert "==" in line, f"unpinned line in the lock file: {line}"
        name, version = line.split("==", 1)
        locked[name.lower().replace("_", "-")] = version

    data = tomllib.loads((ROOT / "pyproject.toml").read_text())
    project = data["project"]
    specs = list(project["dependencies"])
    for extra in project.get("optional-dependencies", {}).values():
        specs.extend(extra)

    for spec in specs:
        name, _, version = spec.partition("==")
        key = name.split("[")[0].strip().lower().replace("_", "-")
        assert key in locked, f"{name} is declared but absent from the lock file"
        assert locked[key] == version, (
            f"{name} is declared as {version} but locked at {locked[key]}"
        )


def test_no_dependency_is_fetched_from_a_url_or_a_git_reference() -> None:
    """Every dependency comes from the index, by name and version."""
    text = (ROOT / "pyproject.toml").read_text()
    for marker in ("git+", "http://", "https://", "file://", " @ "):
        assert marker not in text.split("[project.optional-dependencies]")[0] or (
            marker not in text.split("dependencies = [")[1].split("]")[0]
        ), f"a dependency is sourced from {marker!r}"
