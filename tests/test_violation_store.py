from __future__ import annotations

from datetime import UTC, datetime

from sandbox_runtime.schemas import SandboxViolationEvent
from sandbox_runtime.utils import encode_sandboxed_command
from sandbox_runtime.violation_store import SandboxViolationStore


def _make_violation(
    line: str = "deny file-write*",
    command: str | None = None,
    encoded_command: str | None = None,
) -> SandboxViolationEvent:
    return SandboxViolationEvent(
        line=line,
        command=command,
        encoded_command=encoded_command,
        timestamp=datetime.now(UTC),
    )


class TestAddAndGetViolations:
    # No direct TS `it('...')` equivalent for violation-store unit behavior.
    def test_add_single(self):
        store = SandboxViolationStore()
        v = _make_violation()
        store.add_violation(v)
        assert store.get_count() == 1
        assert store.get_violations() == [v]

    def test_add_multiple(self):
        store = SandboxViolationStore()
        for i in range(5):
            store.add_violation(_make_violation(f"violation {i}"))
        assert store.get_count() == 5

    def test_get_with_limit(self):
        store = SandboxViolationStore()
        for i in range(10):
            store.add_violation(_make_violation(f"v{i}"))
        result = store.get_violations(limit=3)
        assert len(result) == 3
        assert result[0].line == "v7"
        assert result[2].line == "v9"


class TestMaxSizeLimit:
    # No direct TS `it('...')` equivalent for violation-store unit behavior.
    def test_truncates_at_100(self):
        store = SandboxViolationStore()
        for i in range(150):
            store.add_violation(_make_violation(f"v{i}"))
        assert store.get_count() == 100
        # Oldest should be trimmed
        violations = store.get_violations()
        assert violations[0].line == "v50"
        assert violations[-1].line == "v149"


class TestGetViolationsForCommand:
    # No direct TS `it('...')` equivalent for violation-store unit behavior.
    def test_filter_by_command(self):
        store = SandboxViolationStore()
        cmd = "echo test"
        encoded = encode_sandboxed_command(cmd)

        store.add_violation(_make_violation("v1", command=cmd, encoded_command=encoded))
        store.add_violation(
            _make_violation("v2", command="other", encoded_command="xxx")
        )
        store.add_violation(_make_violation("v3", command=cmd, encoded_command=encoded))

        result = store.get_violations_for_command(cmd)
        assert len(result) == 2
        assert result[0].line == "v1"
        assert result[1].line == "v3"

    def test_no_matches(self):
        store = SandboxViolationStore()
        store.add_violation(_make_violation("v1"))
        result = store.get_violations_for_command("nonexistent")
        assert result == []


class TestTotalCountVsCount:
    # No direct TS `it('...')` equivalent for violation-store unit behavior.
    def test_total_persists_after_truncation(self):
        store = SandboxViolationStore()
        for i in range(150):
            store.add_violation(_make_violation(f"v{i}"))
        assert store.get_count() == 100
        assert store.get_total_count() == 150

    def test_total_persists_after_clear(self):
        store = SandboxViolationStore()
        for i in range(5):
            store.add_violation(_make_violation(f"v{i}"))
        store.clear()
        assert store.get_count() == 0
        assert store.get_total_count() == 5


class TestSubscribeAndNotify:
    # No direct TS `it('...')` equivalent for violation-store unit behavior.
    def test_subscribe_gets_initial(self):
        store = SandboxViolationStore()
        store.add_violation(_make_violation("existing"))

        received: list[list[SandboxViolationEvent]] = []
        store.subscribe(lambda vs: received.append(vs))

        # Should have received initial violations on subscribe
        assert len(received) == 1
        assert len(received[0]) == 1

    def test_subscribe_gets_updates(self):
        store = SandboxViolationStore()
        received: list[list[SandboxViolationEvent]] = []
        store.subscribe(lambda vs: received.append(vs))

        store.add_violation(_make_violation("new"))
        # Initial (empty) + after add
        assert len(received) == 2

    def test_unsubscribe(self):
        store = SandboxViolationStore()
        received: list[list[SandboxViolationEvent]] = []
        unsub = store.subscribe(lambda vs: received.append(vs))

        unsub()
        store.add_violation(_make_violation("after unsub"))
        # Only the initial call
        assert len(received) == 1
