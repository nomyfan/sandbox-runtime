from __future__ import annotations

import argparse
import logging
import os
import signal
import subprocess
import sys
import threading

from .config_loader import load_config, load_config_from_string
from .sandbox_manager import SandboxManager
from .schemas import SandboxRuntimeConfig

logger = logging.getLogger(__name__)


def _get_default_config_path() -> str:
    return os.path.join(os.path.expanduser("~"), ".srt-settings.json")


def _get_default_config() -> SandboxRuntimeConfig:
    from .schemas import FilesystemConfig

    return SandboxRuntimeConfig(
        filesystem=FilesystemConfig(
            deny_read=[],
            allow_write=[],
            deny_write=[],
        ),
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="srt",
        description="Run commands in a sandbox with filesystem restrictions",
    )
    parser.add_argument("command_args", nargs="*", metavar="command")
    parser.add_argument(
        "-d", "--debug", action="store_true", help="enable debug logging"
    )
    parser.add_argument(
        "-s",
        "--settings",
        default=None,
        help="path to config file (default: ~/.srt-settings.json)",
    )
    parser.add_argument(
        "-c",
        dest="command_string",
        default=None,
        help="run command string directly (like sh -c)",
    )
    parser.add_argument(
        "--control-fd",
        type=int,
        default=None,
        help="read config updates from file descriptor (JSON lines protocol)",
    )
    parser.add_argument(
        "--enable-log-monitor",
        action="store_true",
        help="enable sandbox violation log monitoring",
    )

    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)

    config_path = args.settings or _get_default_config_path()
    runtime_config = load_config(config_path)
    if runtime_config is None:
        logger.debug("No config found at %s, using default config", config_path)
        runtime_config = _get_default_config()

    manager = SandboxManager()
    manager.initialize(runtime_config, enable_log_monitor=args.enable_log_monitor)

    # Control fd for dynamic config updates
    if args.control_fd is not None:

        def _control_reader() -> None:
            try:
                fd = args.control_fd
                with os.fdopen(fd, "r") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        new_config = load_config_from_string(line)
                        if new_config:
                            logger.debug("Config updated from control fd")
                            manager.update_config(new_config)
                        else:
                            logger.debug(
                                "Invalid config on control fd (ignored): %s",
                                line,
                            )
            except Exception:
                logger.debug("Control fd reader stopped", exc_info=True)

        t = threading.Thread(target=_control_reader, daemon=True)
        t.start()

    # Determine command
    if args.command_string:
        command = args.command_string
    elif args.command_args:
        command = " ".join(args.command_args)
    else:
        print(
            "Error: No command specified. "
            "Use -c <command> or provide command arguments.",
            file=sys.stderr,
        )
        sys.exit(1)

    sandboxed = manager.wrap_command(command)

    child = subprocess.Popen(sandboxed, shell=True)

    def _sigint_handler(sig: int, frame: object) -> None:
        child.send_signal(signal.SIGINT)

    def _sigterm_handler(sig: int, frame: object) -> None:
        child.send_signal(signal.SIGTERM)

    signal.signal(signal.SIGINT, _sigint_handler)
    signal.signal(signal.SIGTERM, _sigterm_handler)

    exit_code = child.wait()
    manager.reset()
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
