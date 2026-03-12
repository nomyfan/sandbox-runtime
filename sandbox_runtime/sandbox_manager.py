from __future__ import annotations

import logging
import os
import random
import shlex
import shutil
import string
import subprocess
import sys
from collections.abc import Callable

from .log_monitor import start_macos_sandbox_log_monitor
from .profile import generate_sandbox_profile
from .schemas import (
    FsReadRestrictionConfig,
    FsWriteRestrictionConfig,
    SandboxRuntimeConfig,
)
from .utils import (
    encode_sandboxed_command,
    get_default_write_paths,
    remove_trailing_glob_suffix,
)
from .violation_store import SandboxViolationStore

logger = logging.getLogger(__name__)


def _random_suffix() -> str:
    chars = string.ascii_lowercase + string.digits
    return "_" + "".join(random.choices(chars, k=9)) + "_SBX"


class SandboxManager:
    def __init__(self) -> None:
        self._config: SandboxRuntimeConfig | None = None
        self._initialized: bool = False
        self._violation_store = SandboxViolationStore()
        self._log_monitor_shutdown: Callable[[], None] | None = None
        self._session_suffix: str = _random_suffix()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def initialize(
        self,
        config: SandboxRuntimeConfig,
        enable_log_monitor: bool = False,
    ) -> None:
        if self._initialized:
            return

        self._config = config

        if enable_log_monitor and sys.platform == "darwin":
            self._log_monitor_shutdown = start_macos_sandbox_log_monitor(
                callback=self._violation_store.add_violation,
                ignore_violations=config.ignore_violations,
                session_suffix=self._session_suffix,
            )
            logger.debug("Started macOS sandbox log monitor")
        elif enable_log_monitor:
            logger.debug("Skipping sandbox log monitor on non-macOS platform")

        self._initialized = True

    def _generate_log_tag(self, command: str) -> str:
        encoded = encode_sandboxed_command(command)
        return f"CMD64_{encoded}_END_{self._session_suffix}"

    def wrap_command(self, command: str, shell: str = "bash") -> str:
        """Generate a sandbox-exec command string.

        Returns the original command if no restrictions apply.
        """
        if self._config is None:
            return command

        read_config = self.get_fs_read_config()
        write_config = self.get_fs_write_config()

        has_read = len(read_config.deny_only) > 0
        has_write = write_config is not None

        if not has_read and not has_write:
            return command

        log_tag = self._generate_log_tag(command)

        profile = generate_sandbox_profile(
            read_config=read_config,
            write_config=write_config,
            allow_pty=self._config.allow_pty,
            allow_git_config=self._config.filesystem.allow_git_config,
            log_tag=log_tag,
        )

        shell_path = shutil.which(shell)
        if shell_path is None:
            raise FileNotFoundError(f"Shell '{shell}' not found in PATH")

        parts = [
            "sandbox-exec",
            "-p",
            profile,
            shell_path,
            "-c",
            command,
        ]
        return shlex.join(parts)

    def execute(
        self, command: str, shell: str = "bash", **kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        """Execute a command inside the sandbox."""
        sandboxed = self.wrap_command(command, shell=shell)
        return subprocess.run(
            sandboxed,
            shell=True,
            text=True,
            capture_output=True,
            **kwargs,  # type: ignore[arg-type]
        )

    def update_config(self, new_config: SandboxRuntimeConfig) -> None:
        self._config = new_config.model_copy(deep=True)
        logger.debug("Sandbox configuration updated")

    def get_fs_read_config(self) -> FsReadRestrictionConfig:
        if self._config is None:
            return FsReadRestrictionConfig(deny_only=[])

        deny_paths: list[str] = []
        for p in self._config.filesystem.deny_read:
            stripped = remove_trailing_glob_suffix(p)
            deny_paths.append(stripped)

        return FsReadRestrictionConfig(deny_only=deny_paths)

    def get_fs_write_config(self) -> FsWriteRestrictionConfig | None:
        if self._config is None:
            return FsWriteRestrictionConfig(
                allow_only=get_default_write_paths(), deny_within_allow=[]
            )

        allow_paths = [
            remove_trailing_glob_suffix(p) for p in self._config.filesystem.allow_write
        ]
        deny_paths = [
            remove_trailing_glob_suffix(p) for p in self._config.filesystem.deny_write
        ]

        return FsWriteRestrictionConfig(
            allow_only=get_default_write_paths() + allow_paths,
            deny_within_allow=deny_paths,
        )

    def get_violation_store(self) -> SandboxViolationStore:
        return self._violation_store

    def annotate_stderr_with_sandbox_failures(self, command: str, stderr: str) -> str:
        if self._config is None:
            return stderr

        violations = self._violation_store.get_violations_for_command(command)
        if not violations:
            return stderr

        annotated = stderr + os.linesep + "<sandbox_violations>" + os.linesep
        for v in violations:
            annotated += v.line + os.linesep
        annotated += "</sandbox_violations>"
        return annotated

    def reset(self) -> None:
        if self._log_monitor_shutdown is not None:
            self._log_monitor_shutdown()
            self._log_monitor_shutdown = None

        self._initialized = False
