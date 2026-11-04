#!/usr/bin/env python3
"""One command setup. Works the same on Windows, Linux and macOS.

    python install.py

Creates the virtual environment, installs the backend dependencies, installs the
frontend packages and builds the UI. Safe to run again: it reuses an existing
environment and only reinstalls what changed.

Run it with the newest Python you have, 3.15 at the time of writing (3.11 is the floor).
It finds the right interpreter inside the virtual environment by itself, so there is
nothing to activate first. An existing environment built on an older Python is rebuilt
on the one running this script.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import venv
from pathlib import Path

ROOT = Path(__file__).resolve().parent
VENV = ROOT / ".venv"
MIN_PYTHON = (3, 11)


def venv_python() -> Path:
    """Interpreter inside the virtual environment. Windows uses Scripts, POSIX uses bin."""
    if os.name == "nt":
        return VENV / "Scripts" / "python.exe"
    return VENV / "bin" / "python"


def venv_version() -> tuple[int, int] | None:
    """Python version the existing venv was built with, None if there is none (or it is
    broken, e.g. its base interpreter got uninstalled)."""
    py = venv_python()
    if not py.exists():
        return None
    try:
        out = subprocess.run(
            [str(py), "-c", "import sys; print(*sys.version_info[:2])"],
            capture_output=True, text=True, timeout=30,
        )
        major, minor = out.stdout.split()
        return int(major), int(minor)
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return None


def run(cmd: list[str], cwd: Path | None = None) -> None:
    printable = " ".join(str(c) for c in cmd)
    print(f"\n> {printable}")
    result = subprocess.run(cmd, cwd=cwd)
    if result.returncode != 0:
        sys.exit(f"\nFailed: {printable}")


def need(tool: str, hint: str) -> str:
    """Locate a required external tool, or stop with an explanation.

    npm is a shell script on Windows (npm.cmd), so shutil.which is the portable way to
    resolve it; calling "npm" directly through subprocess fails there without shell=True.
    """
    found = shutil.which(tool)
    if not found:
        sys.exit(f"'{tool}' was not found on PATH. {hint}")
    return found


def main() -> None:
    if sys.version_info < MIN_PYTHON:
        sys.exit(
            f"Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]} or newer is required, "
            f"this is {sys.version_info.major}.{sys.version_info.minor}."
        )

    npm = need("npm", "Install Node.js from https://nodejs.org and reopen your terminal.")

    print("== virtual environment ==")
    have = venv_version()
    mine = sys.version_info[:2]
    if have is not None and have >= mine:
        print(f"reusing {VENV} (Python {have[0]}.{have[1]})")
    else:
        # a venv on an older python than the one running this gets rebuilt. otherwise
        # it sits on 3.x forever even after a newer python is installed
        if have is not None:
            print(f"{VENV} runs Python {have[0]}.{have[1]}, rebuilding it on {mine[0]}.{mine[1]}")
        venv.EnvBuilder(with_pip=True, clear=True).create(VENV)
        print(f"created {VENV}")
    # pyyaml (via uvicorn[standard]) has no wheel for a brand new python yet and most
    # machines have no compiler, so build it as plain python
    os.environ.setdefault("PYYAML_FORCE_LIBYAML", "0")

    py = str(venv_python())
    print("\n== backend dependencies ==")
    run([py, "-m", "pip", "install", "--upgrade", "pip", "--quiet"])
    run([py, "-m", "pip", "install", "-r", str(ROOT / "backend" / "requirements.txt"), "--quiet"])

    print("\n== frontend ==")
    run([npm, "install"], cwd=ROOT / "frontend")
    run([npm, "run", "build"], cwd=ROOT / "frontend")

    env_file = ROOT / ".env"
    if not env_file.exists():
        shutil.copyfile(ROOT / ".env.example", env_file)
        print(f"\ncreated {env_file} from .env.example")

    launcher = ".venv\\Scripts\\python serve.py" if os.name == "nt" else ".venv/bin/python serve.py"
    print(
        "\nSetup complete.\n\n"
        "Next steps:\n"
        "  1. Open .env and set JWT_SECRET to a long random value. Generate one with:\n"
        f"       {py} -c \"import secrets; print(secrets.token_urlsafe(48))\"\n"
        "  2. Set ADMIN_INITIAL_PASSWORD, or leave it empty to have a random one\n"
        "     printed to the log once on first start.\n"
        f"  3. Start the server:  {launcher}\n"
    )


if __name__ == "__main__":
    main()
