"""
Unit Tests: Event Bus (Core)
============================

Core pub/sub and lifecycle behavior for the EventBus.
See test_event_bus_extended.py for deduplication, DLQ, and edge cases.
"""

from __future__ import annotations

import asyncio

import pytest

from core.events import EventType, OracleEvent
from runtime.event_bus import EventBus, get_event_bus, set_event_bus


class TestEventBusLifecycle:
    """Tests for start/stop behavior."""

    @pytest.mark.asyncio
    async def test_start_sets_running_state(self) -> None:
        bus = EventBus()
        assert bus._running is False

        await bus.start()
        try:
            assert bus._running is True
            health = await bus.health()
            assert health["status"] == "healthy"
        finally:
            await bus.stop()

    @pytest.mark.asyncio
    async def test_stop_is_idempotent(self) -> None:
        bus = EventBus()
        await bus.start()
        await bus.stop()
        # Calling stop again should not raise
        await bus.stop()
        assert bus._running is False

    @pytest.mark.asyncio
    async def test_double_start_warns_but_does_not_raise(self) -> None:
        bus = EventBus()
        await bus.start()
        try:
            await bus.start()  # Should log a warning, not raise
            assert bus._running is True
        finally:
            await bus.stop()


class TestEventBusPublishSubscribe:
    """Tests for basic publish/subscribe delivery."""

    @pytest.mark.asyncio
    async def test_subscriber_receives_published_event(self) -> None:
        bus = EventBus()
        set_event_bus(bus)
        await bus.start()

        received = []

        async def handler(event: OracleEvent) -> None:
            received.append(event)

        bus.subscribe("basic_sub", {EventType.MISSION_CREATED}, handler)

        await bus.publish(OracleEvent(event_type=EventType.MISSION_CREATED, source="test"))
        await asyncio.sleep(0.3)
        await bus.stop()

        assert len(received) == 1
        assert received[0].event_type == EventType.MISSION_CREATED

    @pytest.mark.asyncio
    async def test_publish_before_start_is_ignored(self) -> None:
        bus = EventBus()
        # Bus never started — publish should be a no-op, not raise
        await bus.publish(OracleEvent(event_type=EventType.MISSION_CREATED, source="test"))
        health = await bus.health()
        assert health["queue_size"] == 0

    @pytest.mark.asyncio
    async def test_unsubscribed_handler_receives_nothing(self) -> None:
        bus = EventBus()
        set_event_bus(bus)
        await bus.start()

        received = []

        async def handler(event: OracleEvent) -> None:
            received.append(event)

        bus.subscribe("temp_sub", {EventType.MISSION_CREATED}, handler)
        bus.unsubscribe("temp_sub")

        await bus.publish(OracleEvent(event_type=EventType.MISSION_CREATED, source="test"))
        await asyncio.sleep(0.3)
        await bus.stop()

        assert received == []


class TestEventBusSingleton:
    """Tests for the module-level EventBus singleton helpers."""

    def test_get_event_bus_returns_singleton(self) -> None:
        set_event_bus(None)  # type: ignore[arg-type]
        bus_a = get_event_bus()
        bus_b = get_event_bus()
        assert bus_a is bus_b

    def test_set_event_bus_overrides_singleton(self) -> None:
        custom_bus = EventBus(max_workers=1)
        set_event_bus(custom_bus)
        assert get_event_bus() is custom_bus
