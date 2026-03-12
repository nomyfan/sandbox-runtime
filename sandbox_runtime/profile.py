from __future__ import annotations

import json
import os
import re

from .schemas import FsReadRestrictionConfig, FsWriteRestrictionConfig
from .utils import (
    DANGEROUS_FILES,
    contains_glob_chars,
    get_dangerous_directories,
    glob_to_regex,
    normalize_path_for_sandbox,
)


def escape_path(path_str: str) -> str:
    """Escape a path for use in a sandbox profile using JSON encoding."""
    return json.dumps(path_str)


def _get_ancestor_directories(path_str: str) -> list[str]:
    """Get all ancestor directories up to (but not including) root."""
    ancestors: list[str] = []
    current = os.path.dirname(path_str)
    while current not in ("/", "."):
        ancestors.append(current)
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent
    return ancestors


def get_tmpdir_parent_if_macos_pattern() -> list[str]:
    """Get TMPDIR parent if it matches macOS /var/folders/XX/YYY/T/ pattern.

    Returns both /var/ and /private/var/ versions since /var is a symlink.
    """
    tmpdir = os.environ.get("TMPDIR", "")
    if not tmpdir:
        return []

    if not re.match(r"^/(private/)?var/folders/[^/]{2}/[^/]+/T/?$", tmpdir):
        return []

    parent = re.sub(r"/T/?$", "", tmpdir)

    if parent.startswith("/private/var/"):
        return [parent, parent.replace("/private", "", 1)]
    elif parent.startswith("/var/"):
        return [parent, "/private" + parent]

    return [parent]


def mac_get_mandatory_deny_patterns(allow_git_config: bool = False) -> list[str]:
    """Get mandatory deny patterns for dangerous files and directories."""
    cwd = os.getcwd()
    deny_paths: list[str] = []

    for file_name in DANGEROUS_FILES:
        deny_paths.append(os.path.join(cwd, file_name))
        deny_paths.append(f"**/{file_name}")

    for dir_name in get_dangerous_directories():
        deny_paths.append(os.path.join(cwd, dir_name))
        deny_paths.append(f"**/{dir_name}/**")

    # Git hooks are always blocked
    deny_paths.append(os.path.join(cwd, ".git/hooks"))
    deny_paths.append("**/.git/hooks/**")

    # Git config conditionally blocked
    if not allow_git_config:
        deny_paths.append(os.path.join(cwd, ".git/config"))
        deny_paths.append("**/.git/config")

    return list(dict.fromkeys(deny_paths))  # deduplicate preserving order


def generate_move_blocking_rules(
    path_patterns: list[str],
    log_tag: str,
    allow_paths: list[str] | None = None,
) -> list[str]:
    """Generate deny rules for file-write-unlink to prevent move/rename bypass.

    Args:
        path_patterns: Deny path patterns to generate move-blocking rules for.
        log_tag: Log tag for sandbox violations.
        allow_paths: Allowed write paths. Ancestor deny-unlink rules will not be
            generated for directories that are subpaths of (or equal to) an
            allowed write path, since the user explicitly permitted writes there.
    """
    rules: list[str] = []
    # Normalize allow paths for comparison
    normalized_allow: list[str] = []
    for p in allow_paths or []:
        np = normalize_path_for_sandbox(p)
        if not contains_glob_chars(np):
            normalized_allow.append(np)

    def _is_within_allow(path: str) -> bool:
        """Check if path is equal to or a subpath of any allowed write path."""
        for ap in normalized_allow:
            if path == ap or path.startswith(ap + "/"):
                return True
        return False

    def _add_ancestor_rules(base: str) -> None:
        """Add deny-unlink rules for ancestor directories, skipping allowed paths."""
        for ancestor in _get_ancestor_directories(base):
            if _is_within_allow(ancestor):
                continue
            rules.extend(
                [
                    "(deny file-write-unlink",
                    f"  (literal {escape_path(ancestor)})",
                    f'  (with message "{log_tag}"))',
                ]
            )

    for path_pattern in path_patterns:
        normalized = normalize_path_for_sandbox(path_pattern)

        if contains_glob_chars(normalized):
            regex_pattern = glob_to_regex(normalized)
            rules.extend(
                [
                    "(deny file-write-unlink",
                    f"  (regex {escape_path(regex_pattern)})",
                    f'  (with message "{log_tag}"))',
                ]
            )

            static_prefix = re.split(r"[*?\[\]]", normalized)[0]
            if static_prefix and static_prefix != "/":
                base_dir = (
                    static_prefix[:-1]
                    if static_prefix.endswith("/")
                    else os.path.dirname(static_prefix)
                )
                if not _is_within_allow(base_dir):
                    rules.extend(
                        [
                            "(deny file-write-unlink",
                            f"  (literal {escape_path(base_dir)})",
                            f'  (with message "{log_tag}"))',
                        ]
                    )
                _add_ancestor_rules(base_dir)
        else:
            rules.extend(
                [
                    "(deny file-write-unlink",
                    f"  (subpath {escape_path(normalized)})",
                    f'  (with message "{log_tag}"))',
                ]
            )
            _add_ancestor_rules(normalized)

    return rules


def generate_read_rules(
    config: FsReadRestrictionConfig | None, log_tag: str
) -> list[str]:
    """Generate filesystem read rules for sandbox profile."""
    if config is None:
        return ["(allow file-read*)"]

    rules: list[str] = ["(allow file-read*)"]

    for path_pattern in config.deny_only or []:
        normalized = normalize_path_for_sandbox(path_pattern)
        if contains_glob_chars(normalized):
            regex_pattern = glob_to_regex(normalized)
            rules.extend(
                [
                    "(deny file-read*",
                    f"  (regex {escape_path(regex_pattern)})",
                    f'  (with message "{log_tag}"))',
                ]
            )
        else:
            rules.extend(
                [
                    "(deny file-read*",
                    f"  (subpath {escape_path(normalized)})",
                    f'  (with message "{log_tag}"))',
                ]
            )

    rules.extend(generate_move_blocking_rules(config.deny_only or [], log_tag))
    return rules


def generate_write_rules(
    config: FsWriteRestrictionConfig | None,
    log_tag: str,
    allow_git_config: bool = False,
) -> list[str]:
    """Generate filesystem write rules for sandbox profile."""
    if config is None:
        return ["(allow file-write*)"]

    rules: list[str] = []

    # Auto-allow TMPDIR parent on macOS
    for tmpdir_parent in get_tmpdir_parent_if_macos_pattern():
        normalized = normalize_path_for_sandbox(tmpdir_parent)
        rules.extend(
            [
                "(allow file-write*",
                f"  (subpath {escape_path(normalized)})",
                f'  (with message "{log_tag}"))',
            ]
        )

    # Allow rules
    for path_pattern in config.allow_only or []:
        normalized = normalize_path_for_sandbox(path_pattern)
        if contains_glob_chars(normalized):
            regex_pattern = glob_to_regex(normalized)
            rules.extend(
                [
                    "(allow file-write*",
                    f"  (regex {escape_path(regex_pattern)})",
                    f'  (with message "{log_tag}"))',
                ]
            )
        else:
            rules.extend(
                [
                    "(allow file-write*",
                    f"  (subpath {escape_path(normalized)})",
                    f'  (with message "{log_tag}"))',
                ]
            )

    # Deny rules: user deny + mandatory deny
    deny_paths = list(config.deny_within_allow or []) + mac_get_mandatory_deny_patterns(
        allow_git_config
    )

    for path_pattern in deny_paths:
        normalized = normalize_path_for_sandbox(path_pattern)
        if contains_glob_chars(normalized):
            regex_pattern = glob_to_regex(normalized)
            rules.extend(
                [
                    "(deny file-write*",
                    f"  (regex {escape_path(regex_pattern)})",
                    f'  (with message "{log_tag}"))',
                ]
            )
        else:
            rules.extend(
                [
                    "(deny file-write*",
                    f"  (subpath {escape_path(normalized)})",
                    f'  (with message "{log_tag}"))',
                ]
            )

    rules.extend(
        generate_move_blocking_rules(
            deny_paths, log_tag, allow_paths=list(config.allow_only or [])
        )
    )
    return rules


def generate_sandbox_profile(
    *,
    read_config: FsReadRestrictionConfig | None,
    write_config: FsWriteRestrictionConfig | None,
    allow_pty: bool = False,
    allow_git_config: bool = False,
    log_tag: str,
) -> str:
    """Generate a complete Seatbelt sandbox profile string."""
    profile: list[str] = [
        "(version 1)",
        f'(deny default (with message "{log_tag}"))',
        "",
        f"; LogTag: {log_tag}",
        "",
        "; Essential permissions - based on Chrome sandbox policy",
        "; Process permissions",
        "(allow process-exec)",
        "(allow process-fork)",
        "(allow process-info* (target same-sandbox))",
        "(allow signal (target same-sandbox))",
        "(allow mach-priv-task-port (target same-sandbox))",
        "",
        "; User preferences",
        "(allow user-preference-read)",
        "",
        "; Mach IPC - specific services only (no wildcard)",
        "(allow mach-lookup",
        '  (global-name "com.apple.audio.systemsoundserver")',
        '  (global-name "com.apple.distributed_notifications@Uv3")',
        '  (global-name "com.apple.FontObjectsServer")',
        '  (global-name "com.apple.fonts")',
        '  (global-name "com.apple.logd")',
        '  (global-name "com.apple.lsd.mapdb")',
        '  (global-name "com.apple.PowerManagement.control")',
        '  (global-name "com.apple.system.logger")',
        '  (global-name "com.apple.system.notification_center")',
        '  (global-name "com.apple.system.opendirectoryd.libinfo")',
        '  (global-name "com.apple.system.opendirectoryd.membership")',
        '  (global-name "com.apple.bsd.dirhelper")',
        '  (global-name "com.apple.securityd.xpc")',
        '  (global-name "com.apple.coreservices.launchservicesd")',
        ")",
        "",
        "",
        "; POSIX IPC - shared memory",
        "(allow ipc-posix-shm)",
        "",
        "; POSIX IPC - semaphores for Python multiprocessing",
        "(allow ipc-posix-sem)",
        "",
        "; IOKit - specific operations only",
        "(allow iokit-open",
        '  (iokit-registry-entry-class "IOSurfaceRootUserClient")',
        '  (iokit-registry-entry-class "RootDomainUserClient")',
        '  (iokit-user-client-class "IOSurfaceSendRight")',
        ")",
        "",
        "; IOKit properties",
        "(allow iokit-get-properties)",
        "",
        "; Specific safe system-sockets, doesn't allow network access",
        "(allow system-socket (require-all (socket-domain AF_SYSTEM) (socket-protocol 2)))",  # noqa: E501
        "",
        "; sysctl - specific sysctls only",
        "(allow sysctl-read",
        '  (sysctl-name "hw.activecpu")',
        '  (sysctl-name "hw.busfrequency_compat")',
        '  (sysctl-name "hw.byteorder")',
        '  (sysctl-name "hw.cacheconfig")',
        '  (sysctl-name "hw.cachelinesize_compat")',
        '  (sysctl-name "hw.cpufamily")',
        '  (sysctl-name "hw.cpufrequency")',
        '  (sysctl-name "hw.cpufrequency_compat")',
        '  (sysctl-name "hw.cputype")',
        '  (sysctl-name "hw.l1dcachesize_compat")',
        '  (sysctl-name "hw.l1icachesize_compat")',
        '  (sysctl-name "hw.l2cachesize_compat")',
        '  (sysctl-name "hw.l3cachesize_compat")',
        '  (sysctl-name "hw.logicalcpu")',
        '  (sysctl-name "hw.logicalcpu_max")',
        '  (sysctl-name "hw.machine")',
        '  (sysctl-name "hw.memsize")',
        '  (sysctl-name "hw.ncpu")',
        '  (sysctl-name "hw.nperflevels")',
        '  (sysctl-name "hw.packages")',
        '  (sysctl-name "hw.pagesize_compat")',
        '  (sysctl-name "hw.pagesize")',
        '  (sysctl-name "hw.physicalcpu")',
        '  (sysctl-name "hw.physicalcpu_max")',
        '  (sysctl-name "hw.tbfrequency_compat")',
        '  (sysctl-name "hw.vectorunit")',
        '  (sysctl-name "kern.argmax")',
        '  (sysctl-name "kern.bootargs")',
        '  (sysctl-name "kern.hostname")',
        '  (sysctl-name "kern.maxfiles")',
        '  (sysctl-name "kern.maxfilesperproc")',
        '  (sysctl-name "kern.maxproc")',
        '  (sysctl-name "kern.ngroups")',
        '  (sysctl-name "kern.osproductversion")',
        '  (sysctl-name "kern.osrelease")',
        '  (sysctl-name "kern.ostype")',
        '  (sysctl-name "kern.osvariant_status")',
        '  (sysctl-name "kern.osversion")',
        '  (sysctl-name "kern.secure_kernel")',
        '  (sysctl-name "kern.tcsm_available")',
        '  (sysctl-name "kern.tcsm_enable")',
        '  (sysctl-name "kern.usrstack64")',
        '  (sysctl-name "kern.version")',
        '  (sysctl-name "kern.willshutdown")',
        '  (sysctl-name "machdep.cpu.brand_string")',
        '  (sysctl-name "machdep.ptrauth_enabled")',
        '  (sysctl-name "security.mac.lockdown_mode_state")',
        '  (sysctl-name "sysctl.proc_cputype")',
        '  (sysctl-name "vm.loadavg")',
        '  (sysctl-name-prefix "hw.optional.arm")',
        '  (sysctl-name-prefix "hw.optional.arm.")',
        '  (sysctl-name-prefix "hw.optional.armv8_")',
        '  (sysctl-name-prefix "hw.perflevel")',
        '  (sysctl-name-prefix "kern.proc.all")',
        '  (sysctl-name-prefix "kern.proc.pgrp.")',
        '  (sysctl-name-prefix "kern.proc.pid.")',
        '  (sysctl-name-prefix "machdep.cpu.")',
        '  (sysctl-name-prefix "net.routetable.")',
        ")",
        "",
        "; V8 thread calculations",
        "(allow sysctl-write",
        '  (sysctl-name "kern.tcsm_enable")',
        ")",
        "",
        "; Distributed notifications",
        "(allow distributed-notification-post)",
        "",
        "; Specific mach-lookup permissions for security operations",
        '(allow mach-lookup (global-name "com.apple.SecurityServer"))',
        "",
        "; File I/O on device files",
        '(allow file-ioctl (literal "/dev/null"))',
        '(allow file-ioctl (literal "/dev/zero"))',
        '(allow file-ioctl (literal "/dev/random"))',
        '(allow file-ioctl (literal "/dev/urandom"))',
        '(allow file-ioctl (literal "/dev/dtracehelper"))',
        '(allow file-ioctl (literal "/dev/tty"))',
        "",
        "(allow file-ioctl file-read-data file-write-data",
        "  (require-all",
        '    (literal "/dev/null")',
        "    (vnode-type CHARACTER-DEVICE)",
        "  )",
        ")",
        "",
    ]

    # Network — always allow (no network restriction in Python version)
    profile.append("; Network")
    profile.append("(allow network*)")
    profile.append("")

    # Read rules
    profile.append("; File read")
    profile.extend(generate_read_rules(read_config, log_tag))
    profile.append("")

    # Write rules
    profile.append("; File write")
    profile.extend(generate_write_rules(write_config, log_tag, allow_git_config))

    # PTY support
    if allow_pty:
        profile.append("")
        profile.append("; Pseudo-terminal (pty) support")
        profile.append("(allow pseudo-tty)")
        profile.append("(allow file-ioctl")
        profile.append('  (literal "/dev/ptmx")')
        profile.append('  (regex #"^/dev/ttys")')
        profile.append(")")
        profile.append("(allow file-read* file-write*")
        profile.append('  (literal "/dev/ptmx")')
        profile.append('  (regex #"^/dev/ttys")')
        profile.append(")")

    return "\n".join(profile)
