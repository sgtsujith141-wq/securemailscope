"""Local server entry point (M7).

    python -m securemailscope.backend.server

Binds to 127.0.0.1 by default and prints the token a client needs. It does not
listen on any other interface unless told to, and there is no configuration
that turns on public exposure by accident.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from fastapi import FastAPI

from ..config import AnalysisConfig
from .app import AppState, create_app
from .security import DEFAULT_HOST, DEFAULT_PORT

__all__ = ["DEFAULT_DATA_DIR", "main", "build"]

#: Outside the repository, so an application database and stored captures can
#: never be committed by accident.
DEFAULT_DATA_DIR = Path.home() / ".securemailscope"


def build(
    data_dir: Path | None = None,
    *,
    port: int = DEFAULT_PORT,
    require_token: bool = True,
    config: AnalysisConfig | None = None,
) -> tuple[AppState, FastAPI]:
    state = AppState(data_dir or DEFAULT_DATA_DIR, config=config)
    return state, create_app(state, port=port, require_token=require_token)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--host",
        default=DEFAULT_HOST,
        help="Interface to bind. Defaults to 127.0.0.1; do not expose this publicly.",
    )
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    parser.add_argument(
        "--print-token", action="store_true", help="Print the local API token and exit."
    )
    args = parser.parse_args(argv)

    state, app = build(args.data_dir, port=args.port)

    if args.print_token:
        print(state.token.value)
        state.shutdown()
        return 0

    if args.host not in ("127.0.0.1", "localhost", "::1"):
        print(
            f"refusing to bind {args.host}: this application is local-only and its "
            "security model assumes a loopback interface.",
            file=sys.stderr,
        )
        state.shutdown()
        return 2

    print(f"SecureMailScope API on http://{args.host}:{args.port}")
    print(f"  data directory : {args.data_dir}")
    print(f"  private storage: {state.storage.root}")
    print(f"  API token      : {state.token.value}")
    if state.service.recovered_jobs:
        print(
            f"  note           : {state.service.recovered_jobs} job(s) interrupted by a "
            "previous restart were marked failed; they produced no results."
        )

    import uvicorn

    try:
        uvicorn.run(app, host=args.host, port=args.port, log_level="info", access_log=False)
    finally:
        state.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
