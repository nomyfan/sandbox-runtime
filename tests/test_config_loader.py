from __future__ import annotations

import json
import os
import tempfile

from sandbox_runtime.config_loader import load_config, load_config_from_string
from sandbox_runtime.schemas import SandboxRuntimeConfig

VALID_CONFIG = {
    "filesystem": {
        "deny_read": ["/secret"],
        "allow_write": ["/tmp/test"],
        "deny_write": ["/tmp/test/protected"],
    }
}

VALID_CONFIG_CAMEL = {
    "filesystem": {
        "denyRead": ["/secret-camel"],
        "allowWrite": ["/tmp/test-camel"],
        "denyWrite": ["/tmp/test-camel/protected"],
    },
    "allowPty": True,
    "ignoreViolations": {"*": ["/tmp/ignore-me"]},
}


class TestLoadValidConfig:
    # TS: it('should return valid config for valid file', () => {
    def test_loads_correctly(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(VALID_CONFIG, f)
            f.flush()
            path = f.name
        try:
            config = load_config(path)
            assert config is not None
            assert isinstance(config, SandboxRuntimeConfig)
            assert config.filesystem.deny_read == ["/secret"]
            assert config.filesystem.allow_write == ["/tmp/test"]
        finally:
            os.unlink(path)


class TestLoadInvalidJson:
    # TS: it('should return null and log error for invalid JSON', () => {
    def test_returns_none(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("{invalid json!!!")
            f.flush()
            path = f.name
        try:
            assert load_config(path) is None
        finally:
            os.unlink(path)


class TestLoadEmptyFile:
    # TS: it('should return null for empty file', () => {
    def test_returns_none(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("")
            f.flush()
            path = f.name
        try:
            assert load_config(path) is None
        finally:
            os.unlink(path)


class TestLoadWhitespaceOnlyFile:
    # TS: it('should return null for whitespace-only file', () => {
    def test_returns_none(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("   \n\t  ")
            f.flush()
            path = f.name
        try:
            assert load_config(path) is None
        finally:
            os.unlink(path)


class TestLoadMissingFields:
    # TS: it('should return null and log Zod errors for invalid schema', () => {
    def test_returns_none(self):
        # missing allow_write, deny_write
        incomplete = {"filesystem": {"deny_read": []}}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(incomplete, f)
            f.flush()
            path = f.name
        try:
            assert load_config(path) is None
        finally:
            os.unlink(path)


class TestLoadFromString:
    # TS: it('should return valid config for valid JSON', () => {
    def test_valid(self):
        config = load_config_from_string(json.dumps(VALID_CONFIG))
        assert config is not None
        assert config.filesystem.deny_read == ["/secret"]

    # TS: it('should return null for empty string', () => {
    # TS: it('should return null for whitespace-only string', () => {
    def test_empty_string(self):
        assert load_config_from_string("") is None
        assert load_config_from_string("   ") is None

    # TS: it('should return null for invalid JSON', () => {
    def test_invalid_json(self):
        assert load_config_from_string("{bad}") is None

    # TS: it('should return null for valid JSON with invalid schema', () => {
    def test_invalid_schema(self):
        assert load_config_from_string('{"foo": "bar"}') is None

    def test_valid_camel_case(self):
        config = load_config_from_string(json.dumps(VALID_CONFIG_CAMEL))
        assert config is not None
        assert config.filesystem.deny_read == ["/secret-camel"]
        assert config.filesystem.allow_write == ["/tmp/test-camel"]
        assert config.allow_pty is True
        assert config.ignore_violations == {"*": ["/tmp/ignore-me"]}


class TestLoadNonexistentFile:
    # TS: it('should return null when file does not exist', () => {
    def test_returns_none(self):
        assert load_config("/nonexistent/path/config.json") is None
