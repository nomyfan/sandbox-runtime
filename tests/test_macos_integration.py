from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import sys
import tempfile

import pytest

from sandbox_runtime.sandbox_manager import SandboxManager
from sandbox_runtime.schemas import FilesystemConfig, SandboxRuntimeConfig

pytestmark = pytest.mark.skipif(sys.platform != "darwin", reason="macOS only")


def _run_with_manager(
    *,
    deny_read: list[str],
    allow_write: list[str],
    deny_write: list[str],
    command: str,
) -> subprocess.CompletedProcess[str]:
    manager = SandboxManager()
    manager.initialize(
        SandboxRuntimeConfig(
            filesystem=FilesystemConfig(
                deny_read=deny_read,
                allow_write=allow_write,
                deny_write=deny_write,
            )
        )
    )
    wrapped = manager.wrap_command(command)
    try:
        return subprocess.run(
            wrapped,
            shell=True,
            text=True,
            capture_output=True,
        )
    finally:
        manager.reset()


def test_mandatory_deny_blocks_bashrc_write() -> None:
    # TS it: 'blocks writes to .bashrc'
    if shutil.which("sandbox-exec") is None:
        pytest.skip("sandbox-exec not found")

    with tempfile.TemporaryDirectory(prefix="srt-mandatory-deny-") as tmpdir:
        original_cwd = os.getcwd()
        try:
            os.chdir(tmpdir)
            bashrc = os.path.join(tmpdir, ".bashrc")
            with open(bashrc, "w", encoding="utf-8") as f:
                f.write("ORIGINAL")

            command = f"echo MODIFIED > {shlex.quote(bashrc)}"
            result = _run_with_manager(
                deny_read=[],
                allow_write=["."],
                deny_write=[],
                command=command,
            )

            assert result.returncode != 0
            with open(bashrc, encoding="utf-8") as f:
                assert f.read() == "ORIGINAL"
        finally:
            os.chdir(original_cwd)


def test_read_deny_blocks_move_bypass() -> None:
    # TS it: 'should block moving a read-denied file to a readable location'
    if shutil.which("sandbox-exec") is None:
        pytest.skip("sandbox-exec not found")

    with tempfile.TemporaryDirectory(prefix="srt-read-move-") as tmpdir:
        denied_dir = os.path.join(tmpdir, "denied")
        os.makedirs(denied_dir, exist_ok=True)
        secret_file = os.path.join(denied_dir, "secret.txt")
        moved_file = os.path.join(tmpdir, "moved-secret.txt")

        with open(secret_file, "w", encoding="utf-8") as f:
            f.write("SECRET")

        command = f"mv {shlex.quote(secret_file)} {shlex.quote(moved_file)}"
        result = _run_with_manager(
            deny_read=[denied_dir],
            allow_write=[tmpdir],
            deny_write=[],
            command=command,
        )

        assert result.returncode != 0
        assert os.path.exists(secret_file)
        assert not os.path.exists(moved_file)
