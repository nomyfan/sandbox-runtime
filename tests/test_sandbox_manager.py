from __future__ import annotations

from unittest.mock import patch

from sandbox_runtime.sandbox_manager import SandboxManager
from sandbox_runtime.schemas import FilesystemConfig, SandboxRuntimeConfig


def _basic_config(
    filesystem: dict[str, list[str]] | None = None,
) -> SandboxRuntimeConfig:
    fs_data: dict[str, list[str]] = {
        "deny_read": [],
        "allow_write": ["/tmp/test"],
        "deny_write": [],
    }
    if filesystem:
        fs_data.update(filesystem)
    return SandboxRuntimeConfig(
        filesystem=FilesystemConfig(
            deny_read=fs_data["deny_read"],
            allow_write=fs_data["allow_write"],
            deny_write=fs_data["deny_write"],
        )
    )


class TestInitializeAndWrapCommand:
    # TS it: 'any writeConfig means has restrictions on macOS'
    def test_wrap_returns_sandbox_exec(self):
        mgr = SandboxManager()
        mgr.initialize(_basic_config())
        result = mgr.wrap_command("echo hello")
        assert "sandbox-exec" in result
        assert "echo hello" in result

    # No direct TS `it('...')` equivalent for "manager not initialized" behavior.
    def test_wrap_no_config_returns_original(self):
        mgr = SandboxManager()
        result = mgr.wrap_command("echo hello")
        assert result == "echo hello"

    # TS it: 'any writeConfig means has restrictions on macOS'
    def test_wrap_no_restrictions_returns_original(self):
        mgr = SandboxManager()
        config = _basic_config(
            filesystem={"deny_read": [], "allow_write": [], "deny_write": []}
        )
        mgr.initialize(config)
        # No deny_read and no allow_write → write_config has only defaults
        # so it should still wrap since write_config is not None when config exists
        result = mgr.wrap_command("echo hello")
        assert "sandbox-exec" in result

    # TS it: 'should execute commands with zsh when binShell is specified'
    def test_wrap_uses_specified_shell(self):
        mgr = SandboxManager()
        mgr.initialize(_basic_config())
        result = mgr.wrap_command("echo hello", shell="zsh")
        assert "zsh" in result


class TestUpdateConfig:
    # TS: it('should handle updateConfig called before initialize', async () => {
    def test_update_before_initialize_is_overwritten(self):
        mgr = SandboxManager()
        pre_config = _basic_config(
            filesystem={
                "deny_read": ["/pre-init-only"],
                "allow_write": [],
                "deny_write": [],
            }
        )
        init_config = _basic_config(
            filesystem={
                "deny_read": ["/from-initialize"],
                "allow_write": [],
                "deny_write": [],
            }
        )

        mgr.update_config(pre_config)
        mgr.initialize(init_config)

        read_cfg = mgr.get_fs_read_config()
        assert read_cfg is not None
        assert "/from-initialize" in read_cfg.deny_only
        assert "/pre-init-only" not in read_cfg.deny_only

    # TS it: 'should update network restriction config dynamically'
    def test_update_changes_config(self):
        mgr = SandboxManager()
        mgr.initialize(_basic_config())

        new_config = _basic_config(
            filesystem={
                "deny_read": ["/secret"],
                "allow_write": [],
                "deny_write": [],
            }
        )
        mgr.update_config(new_config)

        read_cfg = mgr.get_fs_read_config()
        assert read_cfg is not None
        assert "/secret" in read_cfg.deny_only


class TestGetFsReadConfig:
    # TS it: 'empty denyOnly means no read restrictions on Linux'
    def test_no_deny_returns_empty_config(self):
        mgr = SandboxManager()
        mgr.initialize(_basic_config())
        cfg = mgr.get_fs_read_config()
        assert cfg.deny_only == []

    # TS it: 'non-empty denyOnly means has read restrictions on Linux'
    def test_with_deny(self):
        mgr = SandboxManager()
        mgr.initialize(
            _basic_config(
                filesystem={
                    "deny_read": ["/secret"],
                    "allow_write": [],
                    "deny_write": [],
                }
            )
        )
        cfg = mgr.get_fs_read_config()
        assert cfg is not None
        assert "/secret" in cfg.deny_only


class TestGetFsWriteConfig:
    # No direct TS `it('...')` equivalent for default write path composition.
    def test_includes_defaults(self):
        mgr = SandboxManager()
        mgr.initialize(_basic_config())
        cfg = mgr.get_fs_write_config()
        assert cfg is not None
        assert "/dev/null" in cfg.allow_only

    # No direct TS `it('...')` equivalent for allow_only composition helper.
    def test_includes_user_paths(self):
        mgr = SandboxManager()
        mgr.initialize(
            _basic_config(
                filesystem={
                    "deny_read": [],
                    "allow_write": ["/my/path"],
                    "deny_write": [],
                }
            )
        )
        cfg = mgr.get_fs_write_config()
        assert cfg is not None
        assert "/my/path" in cfg.allow_only


class TestAnnotateStderr:
    # No direct TS `it('...')` equivalent for annotate helper in Python unit tests.
    def test_no_config_returns_original(self):
        mgr = SandboxManager()
        assert mgr.annotate_stderr_with_sandbox_failures("cmd", "error") == "error"

    # No direct TS `it('...')` equivalent for annotate helper in Python unit tests.
    def test_no_violations_returns_original(self):
        mgr = SandboxManager()
        mgr.initialize(_basic_config())
        assert mgr.annotate_stderr_with_sandbox_failures("cmd", "error") == "error"


class TestReset:
    # TS reset() clears runtime resources but keeps config in memory.
    def test_reset_keeps_config_for_wrap(self):
        mgr = SandboxManager()
        mgr.initialize(_basic_config())
        mgr.reset()
        result = mgr.wrap_command("echo test")
        assert "sandbox-exec" in result


class TestInitializePlatformBehavior:
    # No direct TS `it('...')` equivalent for non-macOS monitor guard.
    def test_enable_log_monitor_skipped_on_non_macos(self):
        mgr = SandboxManager()
        with patch("sandbox_runtime.sandbox_manager.sys.platform", "linux"):
            with patch(
                "sandbox_runtime.sandbox_manager.start_macos_sandbox_log_monitor"
            ) as start_mock:
                mgr.initialize(_basic_config(), enable_log_monitor=True)
                assert start_mock.call_count == 0


class TestInitializeIdempotency:
    # TS it: 'should handle calling initialize multiple times without reset'
    def test_initialize_only_runs_once_until_reset(self):
        mgr = SandboxManager()
        first = _basic_config(
            filesystem={
                "deny_read": ["/first"],
                "allow_write": [],
                "deny_write": [],
            }
        )
        second = _basic_config(
            filesystem={
                "deny_read": ["/second"],
                "allow_write": [],
                "deny_write": [],
            }
        )

        stop_calls = 0

        def _start_monitor(*args, **kwargs):
            del args, kwargs

            def _stop():
                nonlocal stop_calls
                stop_calls += 1

            return _stop

        with patch(
            "sandbox_runtime.sandbox_manager.start_macos_sandbox_log_monitor",
            side_effect=_start_monitor,
        ) as start_mock:
            mgr.initialize(first, enable_log_monitor=True)
            mgr.initialize(second, enable_log_monitor=True)

            assert start_mock.call_count == 1
            read_cfg = mgr.get_fs_read_config()
            assert read_cfg is not None
            assert "/first" in read_cfg.deny_only
            assert "/second" not in read_cfg.deny_only

            mgr.reset()
            assert stop_calls == 1
