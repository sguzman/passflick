#!/usr/bin/env python3
"""Exercise only synthetic encrypted Passflick data through its real CLI.

An isolated private directory protects the fictional CSV, vault, and backups.
A PTY supplies test passphrases without placing secrets in process arguments.
"""

from __future__ import annotations

import errno
import os
import pty
import select
import signal
import stat
import sys
import tempfile
import time
from pathlib import Path

PASSPHRASE = b"fictional-ci-recovery-passphrase-2026"
CSV = b"name,url,username,password\nSmoke Example,https://example.test,synthetic-user,fictional-ci-password\n"
PROMPTS = (
    b"New Passflick passphrase:",
    b"Confirm passphrase:",
    b"Passflick passphrase:",
    b"Backup passphrase:",
)


def run_cli(
    executable: str,
    environment: dict[str, str],
    *args: str,
    passphrase: bytes = PASSPHRASE,
    success: bool = True,
    expected_error: bytes | None = None,
) -> bytes:
    pid, terminal = pty.fork()
    if pid == 0:
        try:
            os.execve(executable, [executable, *args], environment)
        except BaseException:
            os._exit(127)

    output = bytearray()
    scanned = 0
    exit_status = None
    terminal_eof = False
    deadline = time.monotonic() + 45
    try:
        # A child can exit before its PTY output is fully read. Drain the
        # terminal to EOF before inspecting the exit code or parsed output.
        while exit_status is None or not terminal_eof:
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"Passflick {' '.join(args)} exceeded the smoke-test deadline"
                )
            ready, _, _ = select.select([terminal], [], [], 0.1)
            if ready and not terminal_eof:
                try:
                    piece = os.read(terminal, 4096)
                except OSError as error:
                    if error.errno != errno.EIO:
                        raise
                    piece = b""
                if not piece:
                    terminal_eof = True
                else:
                    output.extend(piece)
                    while True:
                        matches = [
                            (output.find(prompt, scanned), len(prompt))
                            for prompt in PROMPTS
                        ]
                        matches = [
                            (position, length)
                            for position, length in matches
                            if position >= 0
                        ]
                        if not matches:
                            break
                        position, length = min(matches)
                        scanned = position + length
                        os.write(terminal, passphrase + b"\n")
            if exit_status is None:
                finished, status = os.waitpid(pid, os.WNOHANG)
                if finished:
                    exit_status = status
    finally:
        os.close(terminal)
        if exit_status is None:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)

    assert os.WIFEXITED(exit_status), f"CLI crashed for {args}"
    result = os.WEXITSTATUS(exit_status)
    assert (result == 0) == success, f"Unexpected CLI exit ({result}) for {args}"
    if expected_error is not None:
        assert not success, "An expected error requires an intentionally failing invocation"
        assert expected_error in output, (
            f"CLI failed for the wrong reason: {' '.join(args)}"
        )
    return bytes(output)


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("Usage: recovery-smoke.py /absolute/path/to/passflick")
    executable = str(Path(sys.argv[1]).resolve(strict=True))

    with tempfile.TemporaryDirectory(prefix="passflick-synthetic-cli-") as temp:
        root = Path(temp)
        vault = root / "vault.passvault"
        export = root / "synthetic-export.csv"
        export.write_bytes(CSV)
        environment = os.environ.copy()
        environment.update({"PASSFLICK_VAULT": str(vault), "XDG_DATA_HOME": temp})

        run_cli(executable, environment, "init")
        assert stat.S_IMODE(vault.stat().st_mode) == 0o600
        run_cli(executable, environment, "import", "edge", str(export))
        prior_to_rejected_imports = vault.read_bytes()

        # An ambiguous password field must not replace the prior source.
        ambiguous_export = root / "ambiguous-export.csv"
        ambiguous_export.write_bytes(
            b"name,url,username,password,pass\n"
            b"Wrong,https://example.test,synthetic-user,one,two\n"
        )
        run_cli(
            executable, environment, "import", "edge", str(ambiguous_export),
            success=False,
            expected_error=b"ambiguous password columns",
        )
        assert vault.read_bytes() == prior_to_rejected_imports

        # A missing username column must not silently erase usernames.
        incomplete_export = root / "incomplete-export.csv"
        incomplete_export.write_bytes(
            b"name,url,password\n"
            b"Wrong,https://example.test,fictional-ci-password\n"
        )
        run_cli(
            executable, environment, "import", "edge", str(incomplete_export),
            success=False,
            expected_error=b"no username column",
        )
        assert vault.read_bytes() == prior_to_rejected_imports
        run_cli(executable, environment, "backup")
        snapshots = list((root / "backups").glob("*.passvault"))
        assert len(snapshots) == 1, "Expected one encrypted snapshot"
        snapshot = snapshots[0]
        assert stat.S_IMODE(snapshot.stat().st_mode) == 0o600
        assert stat.S_IMODE(snapshot.parent.stat().st_mode) == 0o700
        authentic = snapshot.read_bytes()
        assert b"fictional-ci-password" not in authentic
        assert vault.read_bytes() == authentic

        corrupted = bytearray(authentic)
        corrupted[-1] ^= 1
        vault.write_bytes(corrupted)
        run_cli(
            executable, environment, "recover", str(snapshot), "--confirm",
            passphrase=b"fictional-wrong-recovery-passphrase", success=False,
            expected_error=b"vault decryption failed",
        )
        assert vault.read_bytes() == corrupted, "Failed recovery overwrote primary"

        run_cli(executable, environment, "recover", str(snapshot), "--confirm")
        assert vault.read_bytes() == authentic, "Recovered ciphertext differs from backup"
        raw_safety = [
            path for path in (root / "backups").glob("*.passvault")
            if path != snapshot
        ]
        assert len(raw_safety) == 1, "Expected displaced primary safety snapshot"
        assert raw_safety[0].read_bytes() == corrupted
        run_cli(executable, environment, "verify", str(snapshot))
        labels = run_cli(executable, environment, "list")
        assert b"Smoke Example" in labels and b"synthetic-user" in labels
        assert b"fictional-ci-password" not in labels

    print("Synthetic Passflick CLI recovery smoke test passed")


if __name__ == "__main__":
    main()
