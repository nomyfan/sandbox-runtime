from __future__ import annotations

import threading
from collections.abc import Iterator
from unittest.mock import patch

from sandbox_runtime.log_monitor import start_macos_sandbox_log_monitor
from sandbox_runtime.schemas import SandboxViolationEvent
from sandbox_runtime.utils import encode_sandboxed_command


class _FakeProcess:
    def __init__(self, stdout_lines: list[str], stderr_lines: list[str] | None = None):
        self.stdout: Iterator[str] = iter(stdout_lines)
        self.stderr: Iterator[str] = iter(stderr_lines or [])
        self.terminated = False

    def terminate(self) -> None:
        self.terminated = True


class TestMacOSLogMonitor:
    # No direct TS `it('...')` equivalent exists for log monitor parsing tests.
    def test_reports_violation_and_decodes_command(self):
        command = "echo hello"
        encoded = encode_sandboxed_command(command)
        suffix = "_unit_test_SBX"
        line = (
            "2026-03-11 Sandbox: bash(123) deny file-read-data "
            f"/etc/passwd CMD64_{encoded}_END{suffix}\n"
        )
        fake_proc = _FakeProcess([line], [])

        received: list[SandboxViolationEvent] = []
        done = threading.Event()

        def _callback(event: SandboxViolationEvent) -> None:
            received.append(event)
            done.set()

        with patch(
            "sandbox_runtime.log_monitor.subprocess.Popen", return_value=fake_proc
        ):
            stop = start_macos_sandbox_log_monitor(
                callback=_callback,
                ignore_violations=None,
                session_suffix=suffix,
            )

            assert done.wait(0.5), "log monitor did not emit violation event"
            stop()

        assert len(received) == 1
        assert received[0].command == command
        assert received[0].encoded_command == encoded
        assert "deny file-read-data" in received[0].line
        assert fake_proc.terminated is True

    # No direct TS `it('...')` equivalent exists for log monitor parsing tests.
    def test_ignores_matching_violation_patterns(self):
        command = "npm install"
        encoded = encode_sandboxed_command(command)
        line = (
            "2026-03-11 Sandbox: npm(200) deny file-read-data "
            f"/tmp/ignore-me CMD64_{encoded}_END_session\n"
        )
        fake_proc = _FakeProcess([line], [])
        received: list[SandboxViolationEvent] = []

        with patch(
            "sandbox_runtime.log_monitor.subprocess.Popen", return_value=fake_proc
        ):
            stop = start_macos_sandbox_log_monitor(
                callback=received.append,
                ignore_violations={"*": ["/tmp/ignore-me"]},
                session_suffix="_session",
            )
            # Reader consumes from finite iterator immediately.
            threading.Event().wait(0.05)
            stop()

        assert received == []

    def test_associates_split_command_line_with_violation(self):
        # No direct TS `it('...')` equivalent exists for split-line monitor parsing.
        command = "python -c 'print(1)'"
        encoded = encode_sandboxed_command(command)
        suffix = "_split_session_SBX"
        command_line = f"CMD64_{encoded}_END{suffix}\n"
        violation_line = (
            "2026-03-11 Sandbox: python(321) deny file-read-data /etc/hosts\n"
        )
        fake_proc = _FakeProcess([command_line, violation_line], [])

        received: list[SandboxViolationEvent] = []
        done = threading.Event()

        def _callback(event: SandboxViolationEvent) -> None:
            received.append(event)
            done.set()

        with patch(
            "sandbox_runtime.log_monitor.subprocess.Popen", return_value=fake_proc
        ):
            stop = start_macos_sandbox_log_monitor(
                callback=_callback,
                ignore_violations=None,
                session_suffix=suffix,
            )
            assert done.wait(0.5), "log monitor did not emit split-line violation"
            stop()

        assert len(received) == 1
        assert received[0].command == command
        assert received[0].encoded_command == encoded

    def test_command_specific_ignore_works_with_split_lines(self):
        # No direct TS `it('...')` equivalent exists for split-line ignore matching.
        command = "npm install"
        encoded = encode_sandboxed_command(command)
        command_line = f"CMD64_{encoded}_END_split_ignore\n"
        violation_line = (
            "2026-03-11 Sandbox: npm(200) deny file-read-data /tmp/ignore-me\n"
        )
        fake_proc = _FakeProcess([command_line, violation_line], [])
        received: list[SandboxViolationEvent] = []

        with patch(
            "sandbox_runtime.log_monitor.subprocess.Popen", return_value=fake_proc
        ):
            stop = start_macos_sandbox_log_monitor(
                callback=received.append,
                ignore_violations={"npm": ["/tmp/ignore-me"]},
                session_suffix="_split_ignore",
            )
            threading.Event().wait(0.05)
            stop()

        assert received == []
