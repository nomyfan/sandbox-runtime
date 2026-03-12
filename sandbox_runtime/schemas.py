from __future__ import annotations

from datetime import datetime

from pydantic import AliasChoices, BaseModel, ConfigDict, Field


class FsReadRestrictionConfig(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    deny_only: list[str] = Field(
        validation_alias=AliasChoices("deny_only", "denyOnly")
    )


class FsWriteRestrictionConfig(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    allow_only: list[str] = Field(
        validation_alias=AliasChoices("allow_only", "allowOnly")
    )
    deny_within_allow: list[str] = Field(
        validation_alias=AliasChoices("deny_within_allow", "denyWithinAllow")
    )


class FilesystemConfig(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    deny_read: list[str] = Field(
        validation_alias=AliasChoices("deny_read", "denyRead")
    )
    allow_write: list[str] = Field(
        validation_alias=AliasChoices("allow_write", "allowWrite")
    )
    deny_write: list[str] = Field(
        validation_alias=AliasChoices("deny_write", "denyWrite")
    )
    allow_git_config: bool = Field(
        default=False,
        validation_alias=AliasChoices("allow_git_config", "allowGitConfig"),
    )


class SandboxRuntimeConfig(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    filesystem: FilesystemConfig
    ignore_violations: dict[str, list[str]] | None = Field(
        default=None,
        validation_alias=AliasChoices("ignore_violations", "ignoreViolations"),
    )
    allow_pty: bool = Field(
        default=False, validation_alias=AliasChoices("allow_pty", "allowPty")
    )


class SandboxViolationEvent(BaseModel):
    line: str
    command: str | None = None
    encoded_command: str | None = None
    timestamp: datetime
