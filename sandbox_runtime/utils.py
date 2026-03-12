from __future__ import annotations

import base64
import os
import re

DANGEROUS_FILES = (
    ".gitconfig",
    ".gitmodules",
    ".bashrc",
    ".bash_profile",
    ".zshrc",
    ".zprofile",
    ".profile",
    ".ripgreprc",
    ".mcp.json",
)

DANGEROUS_DIRECTORIES = (".git", ".vscode", ".idea")


def get_dangerous_directories() -> list[str]:
    """Get directories to deny writes to.

    Excludes .git since we need it writable for git operations —
    instead we block specific paths within .git (hooks and config).
    """
    return [d for d in DANGEROUS_DIRECTORIES if d != ".git"] + [
        ".claude/commands",
        ".claude/agents",
    ]


def contains_glob_chars(pattern: str) -> bool:
    return any(c in pattern for c in ("*", "?", "[", "]"))


def remove_trailing_glob_suffix(pattern: str) -> str:
    stripped = re.sub(r"/\*\*$", "", pattern)
    return stripped or "/"


def glob_to_regex(glob_pattern: str) -> str:
    """Convert a glob pattern to a regular expression string.

    Supported patterns:
    - ``*`` matches any characters except ``/``
    - ``**`` matches any characters including ``/``
    - ``?`` matches any single character except ``/``
    - ``[abc]`` character class (passed through)
    - ``**/`` matches zero or more directories
    """
    result = glob_pattern
    # Escape regex special characters (except glob chars * ? [ ])
    result = re.sub(r"[.^$+{}()|\\]", lambda m: "\\" + m.group(), result)
    # Escape unclosed brackets
    result = re.sub(r"\[([^\]]*?)$", lambda m: "\\[" + m.group(1), result)
    # Placeholder for **/ and ** before converting *
    result = result.replace("**/", "__GLOBSTAR_SLASH__")
    result = result.replace("**", "__GLOBSTAR__")
    result = result.replace("*", "[^/]*")
    result = result.replace("?", "[^/]")
    result = result.replace("__GLOBSTAR_SLASH__", "(.*/)?")
    result = result.replace("__GLOBSTAR__", ".*")
    return "^" + result + "$"


def normalize_path_for_sandbox(path_pattern: str) -> str:
    """Normalize a path for use in sandbox configurations.

    Handles tilde expansion, relative paths, symlink resolution, and glob patterns.
    """
    cwd = os.getcwd()
    normalized = path_pattern

    if path_pattern == "~":
        normalized = os.path.expanduser("~")
    elif path_pattern.startswith("~/"):
        normalized = os.path.expanduser("~") + path_pattern[1:]
    elif (
        path_pattern.startswith("./")
        or path_pattern.startswith("../")
        or not os.path.isabs(path_pattern)
    ):
        normalized = os.path.normpath(os.path.join(cwd, path_pattern))

    if contains_glob_chars(normalized):
        # For glob patterns, resolve symlinks for the directory portion only
        static_prefix = re.split(r"[*?\[\]]", normalized)[0]
        if static_prefix and static_prefix != "/":
            base_dir = (
                static_prefix[:-1]
                if static_prefix.endswith("/")
                else os.path.dirname(static_prefix)
            )
            try:
                resolved_base = os.path.realpath(base_dir)
                if not is_symlink_outside_boundary(base_dir, resolved_base):
                    suffix = normalized[len(base_dir) :]
                    return resolved_base + suffix
            except OSError:
                pass
        return normalized

    # Non-glob: resolve symlinks
    try:
        resolved = os.path.realpath(normalized)
        if not is_symlink_outside_boundary(normalized, resolved):
            normalized = resolved
    except OSError:
        pass

    return normalized


def is_symlink_outside_boundary(original: str, resolved: str) -> bool:
    """Check if a symlink resolution crosses expected path boundaries."""
    norm_orig = os.path.normpath(original)
    norm_res = os.path.normpath(resolved)

    if norm_res == norm_orig:
        return False

    # Handle macOS symlinks: /tmp -> /private/tmp, /var -> /private/var,
    # /etc -> /private/etc
    _MACOS_PRIVATE_PREFIXES = ("/tmp/", "/var/", "/etc/")
    for prefix in _MACOS_PRIVATE_PREFIXES:
        if norm_orig.startswith(prefix) and norm_res == "/private" + norm_orig:
            return False
        private_prefix = "/private" + prefix
        if norm_orig.startswith(private_prefix) and norm_res == norm_orig:
            return False

    if norm_res == "/":
        return True

    resolved_parts = [p for p in norm_res.split("/") if p]
    if len(resolved_parts) <= 1:
        return True

    if norm_orig.startswith(norm_res + "/"):
        return True

    # Canonical form for macOS
    canonical_orig = norm_orig
    if any(norm_orig.startswith(p) for p in _MACOS_PRIVATE_PREFIXES):
        canonical_orig = "/private" + norm_orig

    if canonical_orig != norm_orig and canonical_orig.startswith(norm_res + "/"):
        return True

    # Strict: resolved must stay within expected path tree
    resolved_same = norm_res == norm_orig
    resolved_is_canonical = canonical_orig != norm_orig and norm_res == canonical_orig
    resolved_starts_orig = norm_res.startswith(norm_orig + "/")
    resolved_starts_canonical = canonical_orig != norm_orig and norm_res.startswith(
        canonical_orig + "/"
    )

    return (
        not resolved_same
        and not resolved_is_canonical
        and not resolved_starts_orig
        and not resolved_starts_canonical
    )


def get_default_write_paths() -> list[str]:
    home = os.path.expanduser("~")
    return [
        "/dev/stdout",
        "/dev/stderr",
        "/dev/null",
        "/dev/tty",
        "/dev/dtracehelper",
        "/dev/autofs_nowait",
        "/tmp/claude",
        "/private/tmp/claude",
        os.path.join(home, ".npm/_logs"),
        os.path.join(home, ".claude/debug"),
    ]


def encode_sandboxed_command(command: str) -> str:
    """Base64 encode the first 100 chars of a command."""
    truncated = command[:100]
    return base64.b64encode(truncated.encode()).decode()


def decode_sandboxed_command(encoded: str) -> str:
    """Decode a base64-encoded command."""
    return base64.b64decode(encoded.encode()).decode()
