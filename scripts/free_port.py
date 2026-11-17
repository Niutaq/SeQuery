#!/usr/bin/env python3
"""Free a TCP port (Windows/macOS/Linux) - used by `task ui`."""
from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys


def pids_on_port(port: int) -> list[int]:
    if sys.platform == "win32":
        try:
            out = subprocess.check_output(
                ["netstat", "-ano", "-p", "tcp"],
                text=True,
                errors="ignore",
            )
        except (OSError, subprocess.CalledProcessError):
            return []
        found: set[int] = set()
        needle = f":{port}"
        for line in out.splitlines():
            if "LISTENING" not in line.upper() and "LISTEN" not in line.upper():
                continue
            if needle not in line:
                continue
            parts = line.split()
            if not parts:
                continue
            try:
                found.add(int(parts[-1]))
            except ValueError:
                continue
        return sorted(pid for pid in found if pid > 0)

    # Unix: lsof
    try:
        out = subprocess.check_output(
            ["lsof", "-ti", f"TCP:{port}", "-sTCP:LISTEN"],
            text=True,
            errors="ignore",
        )
        return [int(x) for x in out.split() if x.strip().isdigit()]
    except (OSError, subprocess.CalledProcessError):
        return []


def kill_pid(pid: int) -> None:
    if sys.platform == "win32":
        subprocess.run(
            ["taskkill", "/PID", str(pid), "/F", "/T"],
            check=False,
            capture_output=True,
        )
        return
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError:
        pass


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--port", type=int, default=8000)
    args = p.parse_args()
    pids = pids_on_port(args.port)
    if not pids:
        print(f"Port {args.port} wolny.")
        return 0
    for pid in pids:
        print(f"Zwalniam port {args.port} (PID {pid})…")
        kill_pid(pid)
    print(f"Port {args.port} zwolniony.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
