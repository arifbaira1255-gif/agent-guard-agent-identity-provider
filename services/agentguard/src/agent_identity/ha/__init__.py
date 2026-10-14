"""Step 7 — distributed high-availability identity service.

This package holds the pieces that let several stateless ``IdentityService`` instances serve
requests safely against shared PostgreSQL (durable, authoritative) and Redis (transient,
distributed) state:

  * ``retry``        — bounded exponential backoff with full jitter
  * ``idempotency``  — tenant-scoped, bounded-retention idempotency for registration/issuance
  * ``coordination`` — advisory-lock job runner so scheduled jobs never run twice concurrently
  * ``health``       — liveness vs readiness aggregation (sanitized, no internal details)
  * ``metrics``      — Step 7 metric names (used with the existing thread-safe Metrics registry)
"""
from .coordination import CoordinationRunner, JobResult, PeriodicScheduler
from .health import HealthAggregator
from .idempotency import (CONFLICT, IN_PROGRESS, NEW, REPLAY, IdempotencyStore,
                          MemoryIdempotencyStore, PgIdempotencyStore, Reservation, request_digest)
from .retry import RetryPolicy, retry_call

__all__ = ["RetryPolicy", "retry_call", "IdempotencyStore", "MemoryIdempotencyStore",
           "PgIdempotencyStore", "Reservation", "request_digest", "NEW", "REPLAY", "IN_PROGRESS",
           "CONFLICT", "CoordinationRunner", "PeriodicScheduler", "JobResult", "HealthAggregator"]
