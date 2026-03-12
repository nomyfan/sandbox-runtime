from __future__ import annotations

import os
from unittest.mock import patch

from sandbox_runtime.profile import (
    generate_move_blocking_rules,
    generate_read_rules,
    generate_sandbox_profile,
    generate_write_rules,
    get_tmpdir_parent_if_macos_pattern,
    mac_get_mandatory_deny_patterns,
)
from sandbox_runtime.schemas import FsReadRestrictionConfig, FsWriteRestrictionConfig
from sandbox_runtime.utils import DANGEROUS_FILES, get_dangerous_directories

LOG_TAG = "CMD64_dGVzdA==_END__test123_SBX"


class TestGenerateSandboxProfileNoRestrictions:
    # No direct TS `it('...')` equivalent for this pure profile-unit shape check.
    def test_allows_all_reads_and_writes(self):
        profile = generate_sandbox_profile(
            read_config=None,
            write_config=None,
            log_tag=LOG_TAG,
        )
        assert "(version 1)" in profile
        assert "(allow file-read*)" in profile
        assert "(allow file-write*)" in profile
        assert "(allow network*)" in profile


class TestGenerateReadRules:
    # No direct TS `it('...')` equivalent for this pure unit-level default behavior.
    def test_no_config(self):
        rules = generate_read_rules(None, LOG_TAG)
        assert rules == ["(allow file-read*)"]

    # TS it: 'should block reading with literal path (regression test)'
    def test_deny_specific_path(self):
        config = FsReadRestrictionConfig(deny_only=["/secret"])
        rules = generate_read_rules(config, LOG_TAG)
        text = "\n".join(rules)
        assert "(allow file-read*)" in text
        assert "(deny file-read*" in text
        assert "/secret" in text

    # TS it: 'should block reading files matching *.env glob pattern via sandbox'
    def test_deny_glob_pattern(self):
        config = FsReadRestrictionConfig(deny_only=["**/.env"])
        rules = generate_read_rules(config, LOG_TAG)
        text = "\n".join(rules)
        assert "(regex" in text

    # TS it: 'should block moving a read-denied file to a readable location'
    def test_includes_move_blocking(self):
        config = FsReadRestrictionConfig(deny_only=["/secret"])
        rules = generate_read_rules(config, LOG_TAG)
        text = "\n".join(rules)
        assert "file-write-unlink" in text


class TestGenerateWriteRules:
    # No direct TS `it('...')` equivalent for this pure unit-level default behavior.
    def test_no_config(self):
        rules = generate_write_rules(None, LOG_TAG)
        assert rules == ["(allow file-write*)"]

    # TS it: 'allows writes to regular files'
    def test_allow_specific_path(self):
        config = FsWriteRestrictionConfig(
            allow_only=["/tmp/myapp"], deny_within_allow=[]
        )
        rules = generate_write_rules(config, LOG_TAG)
        text = "\n".join(rules)
        assert "(allow file-write*" in text
        assert "myapp" in text or "/tmp" in text

    # TS it: 'blocks writes to .bashrc'
    def test_includes_mandatory_deny(self):
        config = FsWriteRestrictionConfig(
            allow_only=["/tmp/myapp"], deny_within_allow=[]
        )
        rules = generate_write_rules(config, LOG_TAG)
        text = "\n".join(rules)
        assert "(deny file-write*" in text
        # Should include dangerous files
        assert ".bashrc" in text or ".gitconfig" in text

    # TS it: 'should still block direct writes to denied paths (sanity check)'
    def test_deny_within_allow(self):
        config = FsWriteRestrictionConfig(
            allow_only=["/workspace"],
            deny_within_allow=["/workspace/secrets"],
        )
        rules = generate_write_rules(config, LOG_TAG)
        text = "\n".join(rules)
        assert "secrets" in text


class TestGenerateMoveBlockingRules:
    # TS it: 'should block moving a read-denied file to a readable location'
    def test_literal_path(self):
        rules = generate_move_blocking_rules(["/protected/dir"], LOG_TAG)
        text = "\n".join(rules)
        assert "(deny file-write-unlink" in text
        assert "(subpath" in text

    # TS it: 'should block moving files matching a glob pattern (*.txt)'
    def test_glob_pattern(self):
        rules = generate_move_blocking_rules(["**/.secret"], LOG_TAG)
        text = "\n".join(rules)
        assert "(deny file-write-unlink" in text
        assert "(regex" in text

    # TS it: 'should block moving an ancestor directory of a read-denied file'
    def test_ancestor_blocking(self):
        rules = generate_move_blocking_rules(["/a/b/c/d"], LOG_TAG)
        text = "\n".join(rules)
        # Should block ancestors
        assert "(literal" in text


class TestMacGetMandatoryDenyPatterns:
    # TS it: 'blocks writes to .bashrc'
    def test_includes_dangerous_files(self):
        patterns = mac_get_mandatory_deny_patterns()
        for f in DANGEROUS_FILES:
            assert any(f in p for p in patterns), f"Missing deny for {f}"

    # TS it: 'blocks writes to .vscode/'
    def test_includes_dangerous_directories(self):
        patterns = mac_get_mandatory_deny_patterns()
        for d in get_dangerous_directories():
            assert any(d in p for p in patterns), f"Missing deny for {d}"

    # TS it: 'always includes .git/hooks in deny patterns regardless of allowGitConfig'
    def test_includes_git_hooks(self):
        patterns = mac_get_mandatory_deny_patterns()
        assert any(".git/hooks" in p for p in patterns)

    # TS it: 'includes .git/config in deny patterns when allowGitConfig is false'
    def test_git_config_blocked_by_default(self):
        patterns = mac_get_mandatory_deny_patterns(allow_git_config=False)
        assert any(".git/config" in p for p in patterns)

    # TS it: 'excludes .git/config from deny patterns when allowGitConfig is true'
    def test_git_config_allowed_when_enabled(self):
        patterns = mac_get_mandatory_deny_patterns(allow_git_config=True)
        # .git/hooks should still be blocked
        assert any(".git/hooks" in p for p in patterns)
        # .git/config should NOT be in deny patterns
        assert not any(p.endswith(".git/config") for p in patterns)

    # No direct TS `it('...')` equivalent for dedup implementation detail.
    def test_no_duplicates(self):
        patterns = mac_get_mandatory_deny_patterns()
        assert len(patterns) == len(set(patterns))


class TestTmpdirParentDetection:
    # No direct TS `it('...')` equivalent for TMPDIR parent helper behavior.
    def test_standard_macos_tmpdir(self):
        with patch.dict(os.environ, {"TMPDIR": "/var/folders/ab/cdefgh/T/"}):
            result = get_tmpdir_parent_if_macos_pattern()
            assert len(result) == 2
            assert "/var/folders/ab/cdefgh" in result
            assert "/private/var/folders/ab/cdefgh" in result

    # No direct TS `it('...')` equivalent for TMPDIR parent helper behavior.
    def test_private_var_tmpdir(self):
        with patch.dict(os.environ, {"TMPDIR": "/private/var/folders/ab/cdefgh/T/"}):
            result = get_tmpdir_parent_if_macos_pattern()
            assert len(result) == 2
            assert "/private/var/folders/ab/cdefgh" in result

    # No direct TS `it('...')` equivalent for TMPDIR parent helper behavior.
    def test_non_macos_tmpdir(self):
        with patch.dict(os.environ, {"TMPDIR": "/tmp"}):
            result = get_tmpdir_parent_if_macos_pattern()
            assert result == []

    # No direct TS `it('...')` equivalent for TMPDIR parent helper behavior.
    def test_no_tmpdir(self):
        with patch.dict(os.environ, {}, clear=True):
            result = get_tmpdir_parent_if_macos_pattern()
            assert result == []
