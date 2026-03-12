from __future__ import annotations

import os
import re

from sandbox_runtime.utils import (
    contains_glob_chars,
    decode_sandboxed_command,
    encode_sandboxed_command,
    get_dangerous_directories,
    glob_to_regex,
    is_symlink_outside_boundary,
    normalize_path_for_sandbox,
)


class TestContainsGlobChars:
    # No direct TS `it('...')` equivalent for containsGlobChars unit checks.
    def test_star(self):
        assert contains_glob_chars("*.txt") is True

    def test_double_star(self):
        assert contains_glob_chars("**/*.ts") is True

    def test_question_mark(self):
        assert contains_glob_chars("file?.txt") is True

    def test_bracket(self):
        assert contains_glob_chars("file[0-9].txt") is True

    def test_no_glob(self):
        assert contains_glob_chars("/usr/local/bin") is False

    def test_empty_string(self):
        assert contains_glob_chars("") is False


class TestGlobToRegex:
    # TS it: 'should convert simple wildcard'
    def test_single_star(self):
        regex = glob_to_regex("*.ts")
        assert re.match(regex, "foo.ts")
        assert not re.match(regex, "foo/bar.ts")

    # TS it: 'should convert globstar pattern'
    def test_double_star(self):
        regex = glob_to_regex("src/**/*.ts")
        assert re.match(regex, "src/foo.ts")
        assert re.match(regex, "src/a/b/c.ts")

    # TS it: 'should convert ? wildcard'
    def test_question_mark(self):
        regex = glob_to_regex("file?.txt")
        assert re.match(regex, "file1.txt")
        assert not re.match(regex, "file12.txt")
        assert not re.match(regex, "file/.txt")

    # No direct TS `it('...')` equivalent for bracket class-specific case.
    def test_bracket_class(self):
        regex = glob_to_regex("file[0-9].txt")
        assert re.match(regex, "file3.txt")
        assert not re.match(regex, "filea.txt")

    # TS it: 'should handle ** without trailing slash'
    def test_globstar_slash(self):
        regex = glob_to_regex("**/node_modules")
        assert re.match(regex, "node_modules")
        assert re.match(regex, "a/b/node_modules")

    # No direct TS `it('...')` equivalent for escaped dot behavior detail.
    def test_escapes_dots(self):
        regex = glob_to_regex("*.env")
        assert re.match(regex, "test.env")
        assert not re.match(regex, "testXenv")

    # No direct TS `it('...')` equivalent for literal path regex conversion.
    def test_literal_path(self):
        regex = glob_to_regex("/usr/local/bin")
        assert re.match(regex, "/usr/local/bin")
        assert not re.match(regex, "/usr/local/bin/foo")


class TestNormalizePathForSandbox:
    # No direct TS `it('...')` equivalent for tilde expansion behavior.
    def test_tilde_expansion(self):
        result = normalize_path_for_sandbox("~/test")
        assert result.startswith(os.path.expanduser("~"))
        assert result.endswith("/test") or result.endswith("\\test")

    # No direct TS `it('...')` equivalent for relative path normalization.
    def test_relative_path(self):
        result = normalize_path_for_sandbox("./foo")
        assert os.path.isabs(result)

    # No direct TS `it('...')` equivalent for absolute path passthrough.
    def test_absolute_path_stays(self):
        result = normalize_path_for_sandbox("/usr/bin")
        assert result == os.path.realpath("/usr/bin")

    # TS it: 'should preserve original glob pattern when base directory symlink
    # points to root'
    def test_glob_pattern_preserved(self):
        result = normalize_path_for_sandbox("/tmp/**/*.log")
        assert "**" in result or "*" in result


class TestIsSymlinkOutsideBoundary:
    # TS it: 'should allow resolution to same path'
    def test_same_path(self):
        assert is_symlink_outside_boundary("/foo/bar", "/foo/bar") is False

    # TS it: 'should allow macOS /tmp -> /private/tmp canonical resolution'
    def test_tmp_to_private_tmp(self):
        result = is_symlink_outside_boundary("/tmp/claude", "/private/tmp/claude")
        assert result is False

    # TS it: 'should allow macOS /var -> /private/var canonical resolution'
    def test_var_to_private_var(self):
        result = is_symlink_outside_boundary(
            "/var/folders/xx", "/private/var/folders/xx"
        )
        assert result is False

    # TS it: 'should detect when symlink points to root'
    def test_root_resolution(self):
        assert is_symlink_outside_boundary("/some/path", "/") is True

    # TS it: 'should detect when symlink points to ancestor directory'
    def test_ancestor_resolution(self):
        assert is_symlink_outside_boundary("/tmp/claude/test", "/tmp") is True

    # TS it: 'should detect when symlink points to unrelated directory'
    def test_outside_tree(self):
        assert is_symlink_outside_boundary("/tmp/claude", "/Users/someone") is True

    # TS it: 'should handle private paths resolving to themselves'
    def test_private_tmp_self(self):
        assert is_symlink_outside_boundary("/private/tmp/x", "/private/tmp/x") is False


class TestEncodeDecode:
    # No direct TS `it('...')` equivalent for command encode/decode helper.
    def test_roundtrip(self):
        original = "echo hello world"
        encoded = encode_sandboxed_command(original)
        decoded = decode_sandboxed_command(encoded)
        assert decoded == original

    # No direct TS `it('...')` equivalent for command truncation helper.
    def test_truncation(self):
        long_cmd = "x" * 200
        encoded = encode_sandboxed_command(long_cmd)
        decoded = decode_sandboxed_command(encoded)
        assert len(decoded) == 100
        assert decoded == "x" * 100


class TestGetDangerousDirectories:
    # TS it: 'allows writes to .git/objects (not hooks/config)'
    def test_excludes_git(self):
        dirs = get_dangerous_directories()
        assert ".git" not in dirs

    # TS it: 'blocks writes to .claude/commands/'
    def test_includes_claude_commands(self):
        dirs = get_dangerous_directories()
        assert ".claude/commands" in dirs

    # TS it: 'blocks writes to .claude/agents/'
    def test_includes_claude_agents(self):
        dirs = get_dangerous_directories()
        assert ".claude/agents" in dirs

    # TS it: 'blocks writes to .vscode/'
    def test_includes_vscode(self):
        dirs = get_dangerous_directories()
        assert ".vscode" in dirs
