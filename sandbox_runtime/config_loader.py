from __future__ import annotations

import json
import sys

from pydantic import ValidationError

from .schemas import SandboxRuntimeConfig


def load_config_from_string(content: str) -> SandboxRuntimeConfig | None:
    """Parse and validate sandbox configuration from a JSON string."""
    if not content.strip():
        return None
    try:
        parsed = json.loads(content)
        return SandboxRuntimeConfig.model_validate(parsed)
    except (json.JSONDecodeError, ValidationError):
        return None


def load_config(file_path: str) -> SandboxRuntimeConfig | None:
    """Load and validate sandbox configuration from a JSON file."""
    try:
        with open(file_path) as f:
            content = f.read()
    except FileNotFoundError:
        return None
    except OSError as exc:
        print(f"Failed to load config from {file_path}: {exc}", file=sys.stderr)
        return None

    if not content.strip():
        return None

    try:
        parsed = json.loads(content)
    except json.JSONDecodeError as exc:
        print(
            f"Invalid JSON in config file {file_path}: {exc}",
            file=sys.stderr,
        )
        return None

    try:
        return SandboxRuntimeConfig.model_validate(parsed)
    except ValidationError as exc:
        print(f"Invalid configuration in {file_path}:", file=sys.stderr)
        for err in exc.errors():
            path = ".".join(str(p) for p in err["loc"])
            print(f"  - {path}: {err['msg']}", file=sys.stderr)
        return None
