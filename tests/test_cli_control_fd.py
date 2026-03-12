from __future__ import annotations

import json
import os
import threading
import time

import pytest

from sandbox_runtime import cli
from sandbox_runtime.schemas import FilesystemConfig, SandboxRuntimeConfig


class _FakeChild:
    def __init__(self, exit_gate: threading.Event):
        self._exit_gate = exit_gate
        self.signals: list[int] = []

    def wait(self) -> int:
        self._exit_gate.wait(0.5)
        return 0

    def send_signal(self, sig: int) -> None:
        self.signals.append(sig)


class _FakeManager:
    def __init__(self, update_gate: threading.Event | None = None):
        self.initialize_calls: list[tuple[SandboxRuntimeConfig, bool]] = []
        self.update_calls: list[SandboxRuntimeConfig] = []
        self.reset_called = False
        self._update_gate = update_gate

    def initialize(
        self, config: SandboxRuntimeConfig, enable_log_monitor: bool = False
    ) -> None:
        self.initialize_calls.append((config, enable_log_monitor))

    def update_config(self, new_config: SandboxRuntimeConfig) -> None:
        self.update_calls.append(new_config)
        if self._update_gate is not None:
            self._update_gate.set()

    def wrap_command(self, command: str) -> str:
        return command

    def reset(self) -> None:
        self.reset_called = True


def _default_config() -> SandboxRuntimeConfig:
    return SandboxRuntimeConfig(
        filesystem=FilesystemConfig(deny_read=[], allow_write=[], deny_write=[])
    )


class TestCliControlFd:
    # TS it: 'should update config when receiving valid JSON on control fd'
    def test_updates_config_from_control_fd_with_camel_case_keys(self, monkeypatch):
        update_gate = threading.Event()
        manager = _FakeManager(update_gate=update_gate)
        child = _FakeChild(exit_gate=update_gate)

        read_fd, write_fd = os.pipe()
        payload = json.dumps(
            {
                "filesystem": {
                    "denyRead": ["/secret/camel"],
                    "allowWrite": ["/tmp/camel"],
                    "denyWrite": ["/tmp/camel/nope"],
                },
                "allowPty": True,
                "ignoreViolations": {"*": ["/tmp/ignore"]},
            }
        )

        def _writer() -> None:
            time.sleep(0.05)
            os.write(write_fd, (payload + "\n").encode())
            os.close(write_fd)

        writer = threading.Thread(target=_writer, daemon=True)
        writer.start()

        monkeypatch.setattr(
            cli.sys, "argv", ["srt", "--control-fd", str(read_fd), "-c", "echo hello"]
        )
        monkeypatch.setattr(cli, "load_config", lambda _: _default_config())
        monkeypatch.setattr(cli, "SandboxManager", lambda: manager)
        monkeypatch.setattr(cli.subprocess, "Popen", lambda *args, **kwargs: child)
        monkeypatch.setattr(cli.signal, "signal", lambda *args, **kwargs: None)

        with pytest.raises(SystemExit) as exc:
            cli.main()

        writer.join(timeout=1)
        assert exc.value.code == 0
        assert manager.reset_called is True
        assert len(manager.update_calls) == 1
        updated = manager.update_calls[0]
        assert updated.filesystem.deny_read == ["/secret/camel"]
        assert updated.filesystem.allow_write == ["/tmp/camel"]
        assert updated.allow_pty is True
        assert updated.ignore_violations == {"*": ["/tmp/ignore"]}

    # TS it: 'should ignore invalid JSON on control fd and continue running'
    def test_ignores_invalid_json_from_control_fd(self, monkeypatch):
        exit_gate = threading.Event()
        manager = _FakeManager()
        child = _FakeChild(exit_gate=exit_gate)

        read_fd, write_fd = os.pipe()

        def _writer() -> None:
            time.sleep(0.05)
            os.write(write_fd, b"{ invalid json }\n")
            os.close(write_fd)
            exit_gate.set()

        writer = threading.Thread(target=_writer, daemon=True)
        writer.start()

        monkeypatch.setattr(
            cli.sys, "argv", ["srt", "--control-fd", str(read_fd), "-c", "echo hello"]
        )
        monkeypatch.setattr(cli, "load_config", lambda _: _default_config())
        monkeypatch.setattr(cli, "SandboxManager", lambda: manager)
        monkeypatch.setattr(cli.subprocess, "Popen", lambda *args, **kwargs: child)
        monkeypatch.setattr(cli.signal, "signal", lambda *args, **kwargs: None)

        with pytest.raises(SystemExit) as exc:
            cli.main()

        writer.join(timeout=1)
        assert exc.value.code == 0
        assert manager.reset_called is True
        assert manager.update_calls == []

    # TS it: 'should ignore empty lines on control fd'
    def test_ignores_empty_lines_on_control_fd(self, monkeypatch):
        exit_gate = threading.Event()
        manager = _FakeManager()
        child = _FakeChild(exit_gate=exit_gate)

        read_fd, write_fd = os.pipe()

        def _writer() -> None:
            time.sleep(0.05)
            os.write(write_fd, b"\n")
            os.write(write_fd, b"   \n")
            os.write(write_fd, b"\t\n")
            os.close(write_fd)
            exit_gate.set()

        writer = threading.Thread(target=_writer, daemon=True)
        writer.start()

        monkeypatch.setattr(
            cli.sys, "argv", ["srt", "--control-fd", str(read_fd), "-c", "echo hello"]
        )
        monkeypatch.setattr(cli, "load_config", lambda _: _default_config())
        monkeypatch.setattr(cli, "SandboxManager", lambda: manager)
        monkeypatch.setattr(cli.subprocess, "Popen", lambda *args, **kwargs: child)
        monkeypatch.setattr(cli.signal, "signal", lambda *args, **kwargs: None)

        with pytest.raises(SystemExit) as exc:
            cli.main()

        writer.join(timeout=1)
        assert exc.value.code == 0
        assert manager.reset_called is True
        assert manager.update_calls == []

    # TS it: 'should work without --control-fd (backward compat)'
    def test_works_without_control_fd(self, monkeypatch):
        exit_gate = threading.Event()
        exit_gate.set()
        manager = _FakeManager()
        child = _FakeChild(exit_gate=exit_gate)

        monkeypatch.setattr(cli.sys, "argv", ["srt", "-c", "echo hello"])
        monkeypatch.setattr(cli, "load_config", lambda _: _default_config())
        monkeypatch.setattr(cli, "SandboxManager", lambda: manager)
        monkeypatch.setattr(cli.subprocess, "Popen", lambda *args, **kwargs: child)
        monkeypatch.setattr(cli.signal, "signal", lambda *args, **kwargs: None)

        with pytest.raises(SystemExit) as exc:
            cli.main()

        assert exc.value.code == 0
        assert manager.reset_called is True
        assert manager.update_calls == []

    # TS it: 'should allow stdin to pass through to child process'
    def test_allows_stdin_to_pass_through_to_child_process(self, monkeypatch):
        exit_gate = threading.Event()
        exit_gate.set()
        manager = _FakeManager()
        child = _FakeChild(exit_gate=exit_gate)
        popen_calls: list[dict[str, object]] = []

        def _fake_popen(*args, **kwargs):
            del args
            popen_calls.append(dict(kwargs))
            return child

        monkeypatch.setattr(cli.sys, "argv", ["srt", "-c", "echo hello"])
        monkeypatch.setattr(cli, "load_config", lambda _: _default_config())
        monkeypatch.setattr(cli, "SandboxManager", lambda: manager)
        monkeypatch.setattr(cli.subprocess, "Popen", _fake_popen)
        monkeypatch.setattr(cli.signal, "signal", lambda *args, **kwargs: None)

        with pytest.raises(SystemExit) as exc:
            cli.main()

        assert exc.value.code == 0
        assert popen_calls
        # No stdin/stdout/stderr override means child inherits stdio from parent.
        assert "stdin" not in popen_calls[0]
        assert "stdout" not in popen_calls[0]
        assert "stderr" not in popen_calls[0]
