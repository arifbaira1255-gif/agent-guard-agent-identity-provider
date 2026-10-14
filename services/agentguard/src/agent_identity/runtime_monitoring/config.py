"""Phase 5 runtime-monitoring configuration.

Fail-closed defaults, environment-driven, and deliberately constrained where a knob could weaken
privacy or open a bypass:

* ``redaction_mode`` has **no "off" option** -- unredacted ingestion is not representable.
* ``retention_days`` must be positive and bounded -- telemetry volume is capped.
* ``sampling_rate`` is clamped to ``(0, 1]`` and never applies to security-critical event classes.
* ``allow_auto_actions`` defaults to **False**: automated response is opt-in, never implicit.

Nothing here is a secret. Configuration is non-secret metadata only.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, replace

from ..core.errors import ValidationError

ENV_VAR = "AGENTGUARD_ENV"

#: Redaction strategies. "off" is intentionally absent -- it cannot be configured.
REDACTION_MODES = ("hash", "mask", "drop")


@dataclass(frozen=True)
class MonitoringConfig:
    environment: str = "development"

    # ---- privacy / redaction -----------------------------------------------------------------
    #: How a sensitive field value is handled. "hash" (default) keeps investigability (stable,
    #: non-reversible digests let an analyst correlate) while never storing the value itself.
    redaction_mode: str = "hash"
    #: Whether full prompt/payload-bearing fields are dropped entirely (they always are).
    drop_payload_fields: bool = True
    #: Maximum nesting depth the redactor will walk in an ``extra`` bag.
    redaction_max_depth: int = 4

    # ---- retention / volume ------------------------------------------------------------------
    retention_days: int = 30
    #: Hard cap on the number of events an in-memory store keeps (bounded memory).
    max_events_retained: int = 200_000

    # ---- sampling ----------------------------------------------------------------------------
    #: Fraction of eligible events stored. Security-critical types are ALWAYS kept.
    sampling_rate: float = 1.0
    #: Whether sampling is enabled at all.
    sampling_enabled: bool = False

    # ---- late / out-of-order handling --------------------------------------------------------
    #: An event whose producer timestamp is more than this many seconds behind the newest event
    #: seen for the tenant is flagged ``late`` (it is still stored, never dropped).
    late_threshold_s: int = 300
    #: Maximum accepted clock skew into the future (epoch-seconds); beyond this the event is
    #: rejected as malformed rather than trusting a bogus timestamp.
    max_future_skew_s: int = 300
    #: Reject events older than this many seconds at ingestion (retention horizon guard).
    max_event_age_s: int = 400 * 24 * 3600

    # ---- behaviour profiles ------------------------------------------------------------------
    default_learning_window_s: int = 7 * 24 * 3600
    default_min_samples: int = 50
    #: Per-hour event count above which frequency is considered abnormal (baseline multiplier).
    frequency_anomaly_multiplier: float = 6.0
    #: Number of authorization failures inside ``rate_window_s`` that is "repeated".
    repeated_denial_threshold: int = 5

    # ---- drift -------------------------------------------------------------------------------
    #: Deviation ratio (observed distinct set vs baseline set) above which a new tool/resource/
    #: destination is a statistical anomaly.
    drift_novelty_ratio: float = 1.5
    #: Whether capability checks are enforced against a declared capability set when available.
    enforce_declared_capabilities: bool = True

    # ---- risk scoring ------------------------------------------------------------------------
    risk_rule_version: str = "phase5-v1"
    risk_window_s: int = 3600
    risk_band_medium: float = 25.0
    risk_band_high: float = 55.0
    risk_band_critical: float = 80.0
    #: Score ceiling (scores are clamped here).
    risk_max: float = 100.0

    # ---- alerts ------------------------------------------------------------------------------
    #: Whether an alert rule may trigger AUTOMATED response actions at all. Default False: turning
    #: automated containment on is an explicit, per-deployment decision.
    allow_auto_actions: bool = False
    default_dedup_window_s: int = 300
    default_rate_window_s: int = 3600
    default_max_alerts_per_window: int = 20

    # ---- correlation -------------------------------------------------------------------------
    #: Window (seconds) within which events sharing a correlation id are treated as one sequence,
    #: and the maximum sequence length materialized (bounded memory for runaway correlation ids).
    max_sequence_length: int = 500

    # ---- audit -------------------------------------------------------------------------------
    audit_enabled: bool = True

    def __post_init__(self):
        if self.environment not in ("development", "staging", "production"):
            raise ValidationError("environment must be development|staging|production")
        if self.redaction_mode not in REDACTION_MODES:
            raise ValidationError(
                "redaction_mode must be one of hash|mask|drop (there is no 'off' option)")
        if not (0.0 < self.sampling_rate <= 1.0):
            raise ValidationError("sampling_rate must be in (0, 1]")
        if not (1 <= self.retention_days <= 3650):
            raise ValidationError("retention_days must be 1..3650")
        if self.max_events_retained < 1:
            raise ValidationError("max_events_retained must be positive")
        if self.late_threshold_s < 0 or self.max_future_skew_s < 0:
            raise ValidationError("skew thresholds must be non-negative")
        if self.default_min_samples < 1:
            raise ValidationError("default_min_samples must be >= 1")
        if self.drift_novelty_ratio < 1.0:
            raise ValidationError("drift_novelty_ratio must be >= 1.0")
        if not (0 < self.risk_band_medium < self.risk_band_high < self.risk_band_critical
                <= self.risk_max):
            raise ValidationError("risk bands must be strictly increasing and <= risk_max")
        if self.frequency_anomaly_multiplier <= 1.0:
            raise ValidationError("frequency_anomaly_multiplier must be > 1.0")
        if self.repeated_denial_threshold < 1:
            raise ValidationError("repeated_denial_threshold must be >= 1")
        if self.max_sequence_length < 1:
            raise ValidationError("max_sequence_length must be >= 1")

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    def with_overrides(self, **kwargs) -> "MonitoringConfig":
        return replace(self, **kwargs)

    @classmethod
    def from_env(cls, **overrides) -> "MonitoringConfig":
        e = os.environ

        def boolean(key, default):
            raw = e.get(key)
            if raw is None:
                return default
            return raw.strip().lower() in ("1", "true", "yes", "on")

        def num(key, default, cast=int):
            raw = e.get(key)
            if raw in (None, ""):
                return default
            try:
                return cast(raw)
            except ValueError:
                raise ValidationError(f"{key} must be a number")

        base = cls(
            environment=(e.get(ENV_VAR, "development").strip().lower() or "development"),
            redaction_mode=(e.get("AGENTGUARD_MONITOR_REDACTION_MODE", "hash").strip().lower()
                            or "hash"),
            drop_payload_fields=boolean("AGENTGUARD_MONITOR_DROP_PAYLOAD_FIELDS", True),
            redaction_max_depth=num("AGENTGUARD_MONITOR_REDACTION_MAX_DEPTH", 4),
            retention_days=num("AGENTGUARD_MONITOR_RETENTION_DAYS", 30),
            max_events_retained=num("AGENTGUARD_MONITOR_MAX_EVENTS", 200_000),
            sampling_rate=num("AGENTGUARD_MONITOR_SAMPLING_RATE", 1.0, float),
            sampling_enabled=boolean("AGENTGUARD_MONITOR_SAMPLING_ENABLED", False),
            late_threshold_s=num("AGENTGUARD_MONITOR_LATE_THRESHOLD_S", 300),
            max_future_skew_s=num("AGENTGUARD_MONITOR_MAX_FUTURE_SKEW_S", 300),
            max_event_age_s=num("AGENTGUARD_MONITOR_MAX_EVENT_AGE_S", 400 * 24 * 3600),
            default_learning_window_s=num("AGENTGUARD_MONITOR_LEARNING_WINDOW_S", 7 * 24 * 3600),
            default_min_samples=num("AGENTGUARD_MONITOR_MIN_SAMPLES", 50),
            frequency_anomaly_multiplier=num("AGENTGUARD_MONITOR_FREQ_MULTIPLIER", 6.0, float),
            repeated_denial_threshold=num("AGENTGUARD_MONITOR_REPEATED_DENIALS", 5),
            drift_novelty_ratio=num("AGENTGUARD_MONITOR_DRIFT_NOVELTY_RATIO", 1.5, float),
            enforce_declared_capabilities=boolean("AGENTGUARD_MONITOR_ENFORCE_CAPABILITIES", True),
            risk_window_s=num("AGENTGUARD_MONITOR_RISK_WINDOW_S", 3600),
            allow_auto_actions=boolean("AGENTGUARD_MONITOR_ALLOW_AUTO_ACTIONS", False),
            default_dedup_window_s=num("AGENTGUARD_MONITOR_DEDUP_WINDOW_S", 300),
            default_rate_window_s=num("AGENTGUARD_MONITOR_RATE_WINDOW_S", 3600),
            default_max_alerts_per_window=num("AGENTGUARD_MONITOR_MAX_ALERTS_PER_WINDOW", 20),
            max_sequence_length=num("AGENTGUARD_MONITOR_MAX_SEQUENCE_LENGTH", 500),
            audit_enabled=boolean("AGENTGUARD_MONITOR_AUDIT_ENABLED", True),
        )
        return base.with_overrides(**overrides) if overrides else base
