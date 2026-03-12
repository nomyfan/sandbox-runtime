from __future__ import annotations

from sandbox_runtime import SandboxManager
from sandbox_runtime.schemas import FilesystemConfig, SandboxRuntimeConfig


def build_manager() -> SandboxManager:
    config = SandboxRuntimeConfig(
        filesystem=FilesystemConfig(
            deny_read=["/etc/passwd"],
            allow_write=["/tmp/myapp"],
            deny_write=["/tmp/myapp/secrets"],
        ),
        allow_pty=True,
    )
    manager = SandboxManager()
    manager.initialize(config)
    return manager


def main() -> None:
    manager = build_manager()
    try:
        result = manager.execute("cat /etc/passwd")
        print(f"Exit code: {result.returncode}")
        if result.stdout.strip():
            print(f"Stdout: {result.stdout.strip()}")
        if result.stderr.strip():
            print(f"Stderr: {result.stderr.strip()}")
    finally:
        manager.reset()


if __name__ == "__main__":
    main()
