"""Local security controls (M7).

"It only listens on localhost" is not a security model. A browser on the same
machine will happily send requests to 127.0.0.1 from any page the user visits,
and DNS rebinding turns an attacker's domain into a local address after the
page has loaded. Both attacks come *from* the local machine, so binding
locally stops neither.

Four controls, each aimed at a specific one of those:

**Host allowlist.** Requests whose ``Host`` header is not a known local name
are refused. This is the DNS-rebinding defence: a rebound name reaches the
socket but arrives with the attacker's hostname in the header.

**Explicit CORS origins.** A fixed list, credentials off, no wildcard. A page
on another origin cannot read a response even if it can cause the request.

**A local token.** Generated at startup, written to a file readable only by
the user, never committed and never embedded in frontend source. It is passed
by the dev server and by the browser client from a runtime fetch, so a
cross-origin page that cannot read the token cannot use the API.

**Conservative error bodies.** Handlers return a short, user-facing reason.
Stack traces, absolute paths and database errors stay in the server log.
"""

from __future__ import annotations

import os
import secrets
from contextlib import suppress
from pathlib import Path
from typing import Final

__all__ = [
    "DEFAULT_HOST",
    "DEFAULT_PORT",
    "ALLOWED_HOSTS",
    "allowed_origins",
    "LocalToken",
    "TOKEN_HEADER",
]

DEFAULT_HOST: Final = "127.0.0.1"
DEFAULT_PORT: Final = 8765

#: Hostnames this API will answer to. Anything else is refused, which is what
#: turns a rebound DNS name into a 400 instead of a successful request.
ALLOWED_HOSTS: Final[tuple[str, ...]] = (
    "127.0.0.1",
    "localhost",
    "[::1]",
    "::1",
)

TOKEN_HEADER: Final = "x-securemailscope-token"

#: The Vite dev server and the built app served from the API itself.
_DEV_ORIGINS: Final[tuple[str, ...]] = (
    "http://127.0.0.1:5173",
    "http://localhost:5173",
)


def allowed_origins(port: int = DEFAULT_PORT) -> list[str]:
    """The explicit origin allowlist. Never ``*``."""
    return [
        *(_DEV_ORIGINS),
        f"http://127.0.0.1:{port}",
        f"http://localhost:{port}",
    ]


class LocalToken:
    """A per-installation token for the local API.

    Stored beside the database, not in the repository, so it cannot be
    committed. Regenerating it is as simple as deleting the file.
    """

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.value = self._load_or_create()

    def _load_or_create(self) -> str:
        override = os.environ.get("SECUREMAILSCOPE_API_TOKEN")
        if override:
            return override
        if self.path.is_file():
            existing = self.path.read_text(encoding="utf-8").strip()
            if existing:
                return existing
        token = secrets.token_urlsafe(32)
        self.path.write_text(token + "\n", encoding="utf-8")
        with suppress(OSError, NotImplementedError):
            os.chmod(self.path, 0o600)
        return token

    def matches(self, candidate: str | None) -> bool:
        """Constant-time comparison, so the token cannot be guessed by timing."""
        if not candidate:
            return False
        return secrets.compare_digest(candidate, self.value)
