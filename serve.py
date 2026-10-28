#!/usr/bin/env python3
"""Start the server. Works the same on Windows, Linux and macOS.

Run it with the interpreter from the virtual environment:

    .venv/Scripts/python serve.py      (Windows)
    .venv/bin/python serve.py          (Linux, macOS)

Why this exists instead of calling uvicorn directly: the bind address and port are
editable in the admin backend, and those values are stored in
``backend/data/runtime_settings.json``. A plain ``uvicorn backend.main:app`` binds its
socket from its own command line before the app ever reads that file, so a port set in
the admin UI would be silently ignored. This launcher loads the stored settings first
and then hands the resolved address to uvicorn.

Precedence, highest first:
  1. --host / --port on the command line
  2. APP_HOST / APP_PORT in the environment
  3. what the admin backend stored
  4. the defaults in backend/config.py

ZIA Live-Flow: live troubleshooting for Zscaler ZIA logs.
Copyright (C) 2026 Niclas Bammert

This program is free software: you can redistribute it and/or modify it under the
terms of the GNU Affero General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE. See the GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License along with
this program. If not, see <https://www.gnu.org/licenses/>.
"""
from __future__ import annotations

import argparse
import os
import pathlib
import sys


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the web UI, API and feed listeners.")
    parser.add_argument("--host", default=None, help="Override the bind address.")
    parser.add_argument("--port", type=int, default=None, help="Override the port.")
    parser.add_argument("--reload", action="store_true", help="Auto reload on code changes (development).")
    parser.add_argument(
        "--proxy-headers",
        action="store_true",
        help="Trust X-Forwarded-* headers. Use this when running behind a reverse proxy.",
    )
    parser.add_argument(
        "--forwarded-allow-ips",
        default=None,
        help="Which proxy addresses may set those headers. Only meaningful with --proxy-headers.",
    )
    args = parser.parse_args()

    try:
        import uvicorn
    except ModuleNotFoundError:
        print(
            "uvicorn is not installed. Did you activate the virtual environment?\n"
            "  Windows: .venv\\Scripts\\python serve.py\n"
            "  Linux:   .venv/bin/python serve.py",
            file=sys.stderr,
        )
        return 1

    from backend import settings_store
    from backend.config import settings

    # Apply the stored admin settings before anything binds a socket. This is the whole
    # point of the launcher, so it happens before we read host and port below.
    settings_store.load_and_apply()

    host = args.host or os.getenv("APP_HOST") or settings.app_host
    port = args.port or int(os.getenv("APP_PORT") or settings.app_port)

    # Resolve against this file, not the working directory. Started from anywhere else,
    # a relative path made the check warn that the UI was missing while the app went on
    # to serve it correctly.
    if not (pathlib.Path(__file__).resolve().parent / "frontend" / "dist" / "index.html").exists():
        print(
            "Warning: frontend/dist is missing, so only the API will respond.\n"
            "Build the UI first:  cd frontend && npm install && npm run build",
            file=sys.stderr,
        )

    print(f"{settings.app_name} listening on http://{host}:{port}")
    uvicorn.run(
        "backend.main:app",
        host=host,
        port=port,
        reload=args.reload,
        proxy_headers=args.proxy_headers,
        forwarded_allow_ips=args.forwarded_allow_ips,
        log_config=None,  # the app configures structlog itself
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
