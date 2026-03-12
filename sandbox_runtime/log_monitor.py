from __future__ import annotations

import logging
import re
import subprocess
import threading
from collections.abc import Callable
from datetime import UTC, datetime

from .schemas import SandboxViolationEvent
from .utils import decode_sandboxed_command

logger = logging.getLogger(__name__)

# Noisy system processes to always filter out
_NOISE_PATTERNS = (
    "mDNSResponder",
    "mach-lookup com.apple.diagnosticd",
    "mach-lookup com.apple.analyticsd",
)


def start_macos_sandbox_log_monitor(
    callback: Callable[[SandboxViolationEvent], None],
    ignore_violations: dict[str, list[str]] | None = None,
    session_suffix: str = "",
) -> Callable[[], None]:
    """Start monitoring macOS system logs for sandbox violations.

    Returns a function that stops the monitor when called.
    """
    cmd_extract_re = re.compile(r"CMD64_(.+?)_END")
    sandbox_extract_re = re.compile(r"Sandbox:\s+(.+)$")

    wildcard_paths = (ignore_violations or {}).get("*", [])
    command_patterns = [
        (pattern, paths)
        for pattern, paths in (ignore_violations or {}).items()
        if pattern != "*"
    ]

    try:
        proc = subprocess.Popen(
            [
                "log",
                "stream",
                "--predicate",
                f'(eventMessage ENDSWITH "{session_suffix}")',
                "--style",
                "compact",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except OSError:
        logger.debug("[Sandbox Monitor] Failed to start log stream", exc_info=True)
        return lambda: None

    pending_command: tuple[str | None, str] | None = None

    def _reader() -> None:
        nonlocal pending_command
        assert proc.stdout is not None
        try:
            for raw_line in proc.stdout:
                line = raw_line.rstrip("\n")
                if not line:
                    continue

                stripped = line.strip()
                if stripped.startswith("CMD64_"):
                    cmd_match = cmd_extract_re.search(stripped)
                    if cmd_match:
                        matched = cmd_match.group(1)
                        decoded: str | None = None
                        if matched is not None:
                            try:
                                decoded = decode_sandboxed_command(matched)
                            except Exception:
                                pass
                            pending_command = (decoded, matched)
                    continue

                # Look for sandbox deny messages
                if "Sandbox:" not in line or "deny" not in line:
                    continue

                sandbox_match = sandbox_extract_re.search(line)
                if not sandbox_match:
                    continue
                violation_details = sandbox_match.group(1)

                # Extract command if present
                command: str | None = None
                encoded_command: str | None = None
                cmd_match = cmd_extract_re.search(line)
                if cmd_match:
                    matched: str | None = cmd_match.group(1)
                    if matched is not None:
                        encoded_command = matched
                        try:
                            command = decode_sandboxed_command(matched)
                        except Exception:
                            pass
                elif pending_command is not None:
                    command, encoded_command = pending_command
                pending_command = None

                # Filter noise
                if any(noise in violation_details for noise in _NOISE_PATTERNS):
                    continue

                # Check ignore_violations
                if ignore_violations and command:
                    if wildcard_paths and any(
                        p in violation_details for p in wildcard_paths
                    ):
                        continue

                    skip = False
                    for pattern, paths in command_patterns:
                        if pattern in command and any(
                            p in violation_details for p in paths
                        ):
                            skip = True
                            break
                    if skip:
                        continue

                callback(
                    SandboxViolationEvent(
                        line=violation_details,
                        command=command,
                        encoded_command=encoded_command,
                        timestamp=datetime.now(UTC),
                    )
                )
        except Exception:
            logger.debug("Log monitor reader stopped", exc_info=True)

    thread = threading.Thread(target=_reader, daemon=True)
    thread.start()

    # Also read stderr in background
    def _stderr_reader() -> None:
        assert proc.stderr is not None
        try:
            for line in proc.stderr:
                logger.debug("[Sandbox Monitor] Log stream stderr: %s", line.rstrip())
        except Exception:
            pass

    stderr_thread = threading.Thread(target=_stderr_reader, daemon=True)
    stderr_thread.start()

    def stop() -> None:
        logger.debug("[Sandbox Monitor] Stopping log monitor")
        try:
            proc.terminate()
        except OSError:
            pass

    return stop
