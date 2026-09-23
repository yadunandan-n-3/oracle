"""
Event Bus
=========

The central nervous system of ORACLE.

Agents NEVER call each other directly.
They publish events. Other agents subscribe.
This is how enterprise systems scale.

Events flow through the Event Bus:
1. Producer publishes an OracleEvent
2. Event Bus routes to all subscribers
3. Subscribers process asynchronously
4. Results published as new events
"""

from __future__ import annotations

import asyncio
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Dict, List, Optional, Set
from uuid import UUID

from core.events import EventEnvelope, EventType, OracleEvent
from core.exceptions import IntegrationError
from core.logging import get_logger
from core.telemetry import telemetry

logger = get_logger(__name__)

# Type alias for event handlers
EventHandler = Callable[[OracleEvent], Awaitable[None]]


class Subscription:
    """
    A registered event subscription.

    Tracks the handler, subscribed event types, and metadata
    for observability and debugging.
    """

    def __init__(
        self,
        subscriber_id: str,
        handler: EventHandler,
        event_types: Set[EventType],
        description: str = "",
    ) -> None:
        self.subscriber_id = subscriber_id
        self.handler = handler
        self.event_types = event_types
        self.description = description
        self.created_at = datetime.now(timezone.utc)
        self.total_events_processed = 0
        self.last_processed_at: Optional[datetime] = None

    def matches(self, event: OracleEvent) -> bool:
        """Check if this subscription matches an event."""
        return event.event_type in self.event_types


class EventBus:
    """
    High-performance async event bus for ORACLE.

    Features:
    - Topic-based publish/subscribe
    - Async delivery with configurable concurrency
    - Automatic retry with backoff
    - Event deduplication
    - Dead letter queue for failed deliveries
    - Health monitoring
    - Telemetry integration
    """

    def __init__(
        self,
        max_workers: int = 10,
        retry_max_attempts: int = 3,
        retry_base_delay: float = 1.0,
        dedup_cache_size: int = 10000,
    ) -> None:
        self._subscriptions: Dict[str, Subscription] = {}
        self._event_type_subscriptions: Dict[EventType, Set[str]] = defaultdict(set)
        self._running = False
        self._worker: Optional[asyncio.Task] = None
        self._event_queue: asyncio.Queue[EventEnvelope] = asyncio.Queue()
        self._dead_letter_queue: List[EventEnvelope] = []
        self._pending_direct_events: List[EventEnvelope] = []

        # Concurrency control
        self._semaphore = asyncio.Semaphore(max_workers)
        self._max_workers = max_workers

        # Retry configuration
        self._retry_max_attempts = retry_max_attempts
        self._retry_base_delay = retry_base_delay

        # Deduplication
        self._dedup_cache: Set[str] = set()
        self._dedup_cache_size = dedup_cache_size

        # Metrics
        self._total_published = 0
        self._total_delivered = 0
        self._total_failed = 0
        self._total_deduplicated = 0

        self._started_at: Optional[datetime] = None

    # ─── Lifecycle ────────────────────────────────────────────────────────

    async def start(self) -> None:
        """Start the event bus worker."""
        if self._running:
            logger.warning("event_bus.already_running")
            return

        self._running = True
        self._started_at = datetime.now(timezone.utc)
        self._worker = asyncio.create_task(self._worker_loop())

        logger.info(
            "event_bus.started",
            max_workers=self._max_workers,
        )

    async def stop(self) -> None:
        """Gracefully stop the event bus."""
        if not self._running:
            return

        self._running = False

        if self._worker:
            self._worker.cancel()
            try:
                await self._worker
            except asyncio.CancelledError:
                pass

        # Process remaining events
        remaining = 0
        try:
            remaining = self._event_queue.qsize()
        except RuntimeError:
            remaining = 0

        if remaining > 0:
            logger.info(
                "event_bus.draining",
                remaining_events=remaining,
            )
            await self._process_remaining_events()

        logger.info(
            "event_bus.stopped",
            published=self._total_published,
            delivered=self._total_delivered,
            failed=self._total_failed,
            deduplicated=self._total_deduplicated,
            dead_letter=len(self._dead_letter_queue),
        )

    async def health(self) -> Dict[str, Any]:
        """Get health status of the event bus."""
        return {
            "status": "healthy" if self._running else "stopped",
            "running": self._running,
            "uptime_seconds": (
                datetime.now(timezone.utc) - self._started_at
            ).total_seconds() if self._started_at else 0,
            "subscriptions": len(self._subscriptions),
            "queue_size": self._event_queue.qsize(),
            "total_published": self._total_published,
            "total_delivered": self._total_delivered,
            "total_failed": self._total_failed,
            "total_deduplicated": self._total_deduplicated,
            "dead_letter_count": len(self._dead_letter_queue),
            "dedup_cache_size": len(self._dedup_cache),
        }

    # ─── Subscription Management ──────────────────────────────────────────

    def subscribe(
        self,
        subscriber_id: str,
        event_types: Set[EventType],
        handler: EventHandler,
        description: str = "",
    ) -> None:
        """
        Subscribe a handler to one or more event types.

        Args:
            subscriber_id: Unique identifier for this subscription
            event_types: Set of event types to subscribe to
            handler: Async callback function
            description: Human-readable description
        """
        if subscriber_id in self._subscriptions:
            logger.warning(
                "event_bus.subscriber_exists",
                subscriber_id=subscriber_id,
            )
            return

        subscription = Subscription(
            subscriber_id=subscriber_id,
            handler=handler,
            event_types=event_types,
            description=description,
        )

        self._subscriptions[subscriber_id] = subscription

        # Index by event type for fast routing
        for event_type in event_types:
            self._event_type_subscriptions[event_type].add(subscriber_id)

        logger.debug(
            "event_bus.subscribed",
            subscriber_id=subscriber_id,
            event_types=[et.value for et in event_types],
        )

    def unsubscribe(self, subscriber_id: str) -> None:
        """
        Remove a subscription.

        Args:
            subscriber_id: ID of the subscription to remove
        """
        subscription = self._subscriptions.pop(subscriber_id, None)
        if subscription:
            for event_type in subscription.event_types:
                self._event_type_subscriptions[event_type].discard(subscriber_id)

            logger.debug(
                "event_bus.unsubscribed",
                subscriber_id=subscriber_id,
            )

    def get_subscriptions(self) -> List[Dict[str, Any]]:
        """Get all active subscriptions."""
        return [
            {
                "subscriber_id": sub.subscriber_id,
                "description": sub.description,
                "event_types": [et.value for et in sub.event_types],
                "total_processed": sub.total_events_processed,
                "created_at": sub.created_at.isoformat(),
            }
            for sub in self._subscriptions.values()
        ]

    # ─── Publishing ───────────────────────────────────────────────────────

    async def publish(
        self,
        event: OracleEvent,
        priority: int = 0,
        ttl_seconds: int = 300,
    ) -> None:
        """
        Publish an event to the event bus.

        The event is queued and delivered asynchronously to all
        matching subscribers.

        Args:
            event: The event to publish
            priority: Priority level (lower = higher priority)
            ttl_seconds: Time-to-live for the event
        """
        if not self._running:
            logger.warning("event_bus.not_running", event_type=event.event_type.value)
            return

        # Deduplication check
        dedup_key = f"{event.event_type.value}:{event.id}"
        if dedup_key in self._dedup_cache:
            self._total_deduplicated += 1
            logger.debug("event_bus.deduplicated", event_id=str(event.id))
            return

        # Add to dedup cache
        self._dedup_cache.add(dedup_key)
        if len(self._dedup_cache) > self._dedup_cache_size:
            # Trim oldest entries
            self._dedup_cache = set(list(self._dedup_cache)[-self._dedup_cache_size // 2 :])

        # Create envelope and queue
        envelope = EventEnvelope(
            event=event,
            priority=priority,
            ttl_seconds=ttl_seconds,
        )

        try:
            await self._event_queue.put(envelope)
        except RuntimeError:
            self._pending_direct_events.append(envelope)
            asyncio.create_task(self._deliver_event(envelope))

        self._total_published += 1

        telemetry.increment_counter(
            "event_bus.published",
            attributes={
                "event_type": event.event_type.value,
                "source": event.source,
            },
        )

        logger.debug(
            "event_bus.published",
            event_id=str(event.id),
            event_type=event.event_type.value,
            source=event.source,
        )

    # ─── Worker Loop ─────────────────────────────────────────────────────

    async def _worker_loop(self) -> None:
        """Background loop that processes events from the queue."""
        while self._running:
            try:
                envelope = await self._event_queue.get()
                asyncio.create_task(self._deliver_event(envelope))
            except asyncio.CancelledError:
                break
            except RuntimeError as e:
                logger.warning("event_bus.loop_mismatch", error=str(e))
                break
            except Exception as e:
                logger.error("event_bus.worker_error", error=str(e))

    async def _deliver_event(self, envelope: EventEnvelope) -> None:
        """
        Deliver an event to all matching subscribers.

        Handles retry logic, dead letter queue, and telemetry.

        Args:
            envelope: The event envelope to deliver
        """
        event = envelope.event
        matching_subscribers = self._event_type_subscriptions.get(event.event_type, set())

        if not matching_subscribers:
            logger.debug(
                "event_bus.no_subscribers",
                event_type=event.event_type.value,
            )
            return

        # Deliver to all matching subscribers concurrently
        tasks = []
        for subscriber_id in matching_subscribers:
            subscription = self._subscriptions.get(subscriber_id)
            if subscription:
                tasks.append(
                    self._deliver_to_subscriber(subscription, envelope)
                )

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _deliver_to_subscriber(
        self,
        subscription: Subscription,
        envelope: EventEnvelope,
    ) -> None:
        """
        Deliver an event to a single subscriber with retry logic.

        Args:
            subscription: The subscriber to deliver to
            envelope: The event envelope
        """
        event = envelope.event
        attempt = 0

        while attempt < self._retry_max_attempts:
            try:
                async with self._semaphore:
                    await subscription.handler(event)

                # Success
                subscription.total_events_processed += 1
                subscription.last_processed_at = datetime.now(timezone.utc)
                self._total_delivered += 1

                telemetry.increment_counter(
                    "event_bus.delivered",
                    attributes={
                        "subscriber": subscription.subscriber_id,
                        "event_type": event.event_type.value,
                    },
                )

                return

            except asyncio.CancelledError:
                raise

            except Exception as e:
                attempt += 1
                envelope.delivery_attempts = attempt
                envelope.last_error = str(e)

                if attempt < self._retry_max_attempts:
                    # Exponential backoff
                    delay = self._retry_base_delay * (2 ** (attempt - 1))
                    logger.warning(
                        "event_bus.retry",
                        subscriber_id=subscription.subscriber_id,
                        event_id=str(event.id),
                        attempt=attempt,
                        delay=delay,
                        error=str(e),
                    )
                    await asyncio.sleep(delay)
                else:
                    # Max retries exceeded — send to dead letter queue
                    self._dead_letter_queue.append(envelope)
                    self._total_failed += 1

                    telemetry.increment_counter(
                        "event_bus.failed",
                        attributes={
                            "subscriber": subscription.subscriber_id,
                            "event_type": event.event_type.value,
                            "error": str(e)[:100],
                        },
                    )

                    logger.error(
                        "event_bus.dead_letter",
                        subscriber_id=subscription.subscriber_id,
                        event_id=str(event.id),
                        error=str(e),
                    )

    # ─── Remaining Events Processing ─────────────────────────────────────

    async def _process_remaining_events(self) -> None:
        """Process any remaining events in the queue during shutdown."""
        while True:
            try:
                if self._event_queue.empty():
                    break
                envelope = self._event_queue.get_nowait()
                await self._deliver_event(envelope)
            except asyncio.QueueEmpty:
                break
            except RuntimeError as e:
                logger.warning("event_bus.drain_loop_mismatch", error=str(e))
                break
            except Exception as e:
                logger.error("event_bus.drain_error", error=str(e))

    # ─── Dead Letter Queue ───────────────────────────────────────────────

    def get_dead_letter_queue(self) -> List[Dict[str, Any]]:
        """Get failed events from the dead letter queue."""
        return [
            {
                "event_id": str(env.event.id),
                "event_type": env.event.event_type.value,
                "source": env.event.source,
                "last_error": env.last_error,
                "delivery_attempts": env.delivery_attempts,
                "created_at": env.created_at.isoformat(),
            }
            for env in self._dead_letter_queue
        ]

    def replay_dead_letter(self, max_events: int = 10) -> int:
        """
        Replay events from the dead letter queue.

        Args:
            max_events: Maximum number of events to replay

        Returns:
            Number of events replayed
        """
        replayed = 0
        remaining: List[EventEnvelope] = []

        for env in self._dead_letter_queue:
            if replayed < max_events:
                asyncio.create_task(self._deliver_event(env))
                replayed += 1
            else:
                remaining.append(env)

        self._dead_letter_queue = remaining
        return replayed


# Global Event Bus instance
_event_bus: Optional[EventBus] = None


def get_event_bus() -> EventBus:
    """Get or create the global EventBus singleton."""
    global _event_bus
    if _event_bus is None:
        _event_bus = EventBus()
    return _event_bus


def set_event_bus(bus: EventBus) -> None:
    """Set the global EventBus instance (useful for testing)."""
    global _event_bus
    _event_bus = bus


__all__ = ["EventBus", "Subscription", "get_event_bus", "set_event_bus"]
