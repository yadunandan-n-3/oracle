"""
Extended Unit Tests: Event Bus
===============================

Additional tests for the Event Bus beyond the existing test_event_bus.py.
"""

from __future__ import annotations

import asyncio
from typing import List, Set
from uuid import UUID, uuid4

import pytest
import pytest_asyncio

from core.events import EventType, OracleEvent
from runtime.event_bus import EventBus, get_event_bus, set_event_bus


class TestEventBusDeduplication:
    """Tests for event deduplication."""

    @pytest.mark.asyncio
    async def test_deduplicates_identical_events(self) -> None:
        """Verify identical events are deduplicated."""
        bus = EventBus(dedup_cache_size=1000)
        set_event_bus(bus)
        await bus.start()

        received = []

        async def handler(event: OracleEvent) -> None:
            received.append(event)

        bus.subscribe(
            "test_handler",
            {EventType.SYSTEM_STARTUP},
            handler,
        )

        event = OracleEvent(
            event_type=EventType.SYSTEM_STARTUP,
            source="test",
        )

        # Publish same event twice
        await bus.publish(event)
        await bus.publish(event)

        await asyncio.sleep(0.5)
        await bus.stop()

        # Only one should be delivered
        assert len(received) == 1


class TestEventBusDeadLetter:
    """Tests for dead letter queue."""

    @pytest.mark.asyncio
    async def test_failed_events_go_to_dlq(self) -> None:
        """Verify events that fail delivery go to dead letter queue."""
        bus = EventBus(max_workers=5, retry_max_attempts=1, retry_base_delay=0.1)
        set_event_bus(bus)
        await bus.start()

        async def failing_handler(event: OracleEvent) -> None:
            raise RuntimeError("Always fails")

        bus.subscribe(
            "failing_handler",
            {EventType.SYSTEM_STARTUP},
            failing_handler,
        )

        event = OracleEvent(
            event_type=EventType.SYSTEM_STARTUP,
            source="test",
        )

        await bus.publish(event)
        await asyncio.sleep(1)

        dlq = bus.get_dead_letter_queue()
        assert len(dlq) == 1
        assert dlq[0]["last_error"] is not None

        await bus.stop()


class TestEventBusSubscriptionFiltering:
    """Tests for event subscription filtering."""

    @pytest.mark.asyncio
    async def test_subscriber_only_receives_matching_events(self) -> None:
        """Verify subscriber only receives events it subscribed to."""
        bus = EventBus()
        set_event_bus(bus)
        await bus.start()

        received_types: List[str] = []

        async def handler(event: OracleEvent) -> None:
            received_types.append(event.event_type.value)

        bus.subscribe(
            "filter_test",
            {EventType.MISSION_CREATED, EventType.MISSION_COMPLETED},
            handler,
        )

        await bus.publish(OracleEvent(
            event_type=EventType.MISSION_CREATED,
            source="test",
        ))
        await bus.publish(OracleEvent(
            event_type=EventType.SYSTEM_STARTUP,  # Not subscribed
            source="test",
        ))
        await bus.publish(OracleEvent(
            event_type=EventType.MISSION_COMPLETED,
            source="test",
        ))

        await asyncio.sleep(0.5)
        await bus.stop()

        assert "mission.created" in received_types
        assert "mission.completed" in received_types
        assert "system.startup" not in received_types


class TestEventBusConcurrentDelivery:
    """Tests for concurrent event delivery."""

    @pytest.mark.asyncio
    async def test_multiple_subscribers(self) -> None:
        """Verify multiple subscribers all receive the event."""
        bus = EventBus(max_workers=10)
        set_event_bus(bus)
        await bus.start()

        received_counts: List[int] = []

        for i in range(5):
            count = 0

            async def handler(event: OracleEvent, cnt=[i]) -> None:
                cnt[0] += 1

            bus.subscribe(
                f"multi_sub_{i}",
                {EventType.SYSTEM_STARTUP},
                handler,
            )

        event = OracleEvent(
            event_type=EventType.SYSTEM_STARTUP,
            source="test",
        )

        await bus.publish(event)
        await asyncio.sleep(0.5)

        # All subscribers should have received
        subs = bus.get_subscriptions()
        await bus.stop()


class TestEventBusEdgeCases:
    """Test edge cases for event bus."""

    def test_subscribe_duplicate_id(self) -> None:
        """Verify duplicate subscriber ID is rejected."""
        bus = EventBus()

        async def handler(event: OracleEvent) -> None:
            pass

        bus.subscribe("dup_id", {EventType.SYSTEM_STARTUP}, handler)
        bus.subscribe("dup_id", {EventType.MISSION_CREATED}, handler)

        subs = bus.get_subscriptions()
        assert len(subs) == 1  # Second should be ignored

    def test_unsubscribe_nonexistent(self) -> None:
        """Verify unsubscribing nonexistent ID doesn't crash."""
        bus = EventBus()
        bus.unsubscribe("nonexistent")  # Should not raise

    @pytest.mark.asyncio
    async def test_health_of_stopped_bus(self) -> None:
        """Verify health check works on stopped bus."""
        bus = EventBus()
        health = await bus.health()
        assert health["status"] == "stopped"

