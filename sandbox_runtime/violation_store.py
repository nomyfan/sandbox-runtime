from __future__ import annotations

from collections.abc import Callable

from .schemas import SandboxViolationEvent
from .utils import encode_sandboxed_command


class SandboxViolationStore:
    """In-memory tail for sandbox violations."""

    def __init__(self) -> None:
        self._violations: list[SandboxViolationEvent] = []
        self._total_count: int = 0
        self._max_size: int = 100
        self._listeners: set[Callable[[list[SandboxViolationEvent]], None]] = set()

    def add_violation(self, violation: SandboxViolationEvent) -> None:
        self._violations.append(violation)
        self._total_count += 1
        if len(self._violations) > self._max_size:
            self._violations = self._violations[-self._max_size :]
        self._notify_listeners()

    def get_violations(self, limit: int | None = None) -> list[SandboxViolationEvent]:
        if limit is None:
            return list(self._violations)
        return self._violations[-limit:]

    def get_count(self) -> int:
        return len(self._violations)

    def get_total_count(self) -> int:
        return self._total_count

    def get_violations_for_command(self, command: str) -> list[SandboxViolationEvent]:
        command_b64 = encode_sandboxed_command(command)
        return [v for v in self._violations if v.encoded_command == command_b64]

    def clear(self) -> None:
        self._violations = []
        # Don't reset total_count when clearing
        self._notify_listeners()

    def subscribe(
        self, listener: Callable[[list[SandboxViolationEvent]], None]
    ) -> Callable[[], None]:
        """Subscribe to violation events. Returns an unsubscribe function."""
        self._listeners.add(listener)
        listener(self.get_violations())

        def unsubscribe() -> None:
            self._listeners.discard(listener)

        return unsubscribe

    def _notify_listeners(self) -> None:
        violations = self.get_violations()
        for listener in self._listeners:
            listener(violations)
