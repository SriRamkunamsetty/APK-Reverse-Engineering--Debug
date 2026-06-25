"""
RAKSHAK — Real-Time Event Bus
Broadcasts pipeline events to all connected WebSocket clients via pub/sub
Zero polling. Pure push. Every engine emits events as they happen.
"""

import asyncio, json, time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any
from enum import Enum


class EventType(str, Enum):
    # Pipeline lifecycle
    ANALYSIS_START     = "analysis_start"
    ANALYSIS_COMPLETE  = "analysis_complete"
    ANALYSIS_ERROR     = "analysis_error"

    # Per-engine events
    HASH_COMPLETE      = "hash_complete"
    STRUCTURE_COMPLETE = "structure_complete"
    MANIFEST_COMPLETE  = "manifest_complete"
    STRINGS_COMPLETE   = "strings_complete"
    STATIC_FINDING     = "static_finding"        # fires for EACH finding
    STATIC_COMPLETE    = "static_complete"
    YARA_MATCH         = "yara_match"            # fires for EACH rule match
    YARA_COMPLETE      = "yara_complete"
    GENAI_THINKING     = "genai_thinking"        # streamed tokens
    GENAI_COMPLETE     = "genai_complete"
    SCORE_UPDATE       = "score_update"          # fires as dimensions computed
    SCORE_FINAL        = "score_final"
    REPORT_READY       = "report_ready"

    # Intelligence alerts
    APT_DETECTED       = "apt_detected"
    NATION_STATE       = "nation_state_alert"
    C2_FOUND           = "c2_found"
    BANKING_THREAT     = "banking_threat"
    CRITICAL_VULN      = "critical_vuln"

    # Network analysis
    IOC_ENRICHED       = "ioc_enriched"


class AnalysisEvent:
    """A single event emitted during analysis"""
    def __init__(self, event_type: EventType, case_id: str,
                 data: dict = None, severity: str = "INFO"):
        self.event_type = event_type
        self.case_id    = case_id
        self.data       = data or {}
        self.severity   = severity
        self.timestamp  = datetime.now(timezone.utc).isoformat()
        self.seq        = int(time.time() * 1000)

    def to_json(self) -> str:
        return json.dumps({
            "type"     : self.event_type,
            "case_id"  : self.case_id,
            "severity" : self.severity,
            "timestamp": self.timestamp,
            "seq"      : self.seq,
            "data"     : self.data,
        })


class EventBus:
    """
    RAKSHAK Real-Time Event Bus
    Manages WebSocket subscriber registry and broadcasts analysis events
    Supports per-case subscriptions and global broadcast
    """

    def __init__(self):
        # case_id → set of WebSocket queues
        self._subscribers: dict[str, set[asyncio.Queue]] = defaultdict(set)
        # Global subscribers (receive ALL events)
        self._global: set[asyncio.Queue] = set()
        # Event history per case (last 200 events)
        self._history: dict[str, list[dict]] = defaultdict(list)

    # ── Subscription management ───────────────────────────────────────────────
    def subscribe(self, case_id: str | None = None) -> asyncio.Queue:
        """Create a queue and register it. case_id=None = global subscriber."""
        q: asyncio.Queue = asyncio.Queue(maxsize=500)
        if case_id:
            self._subscribers[case_id].add(q)
        else:
            self._global.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue, case_id: str | None = None):
        """Remove a queue from the registry."""
        if case_id:
            self._subscribers[case_id].discard(q)
        else:
            self._global.discard(q)

    # ── Event emission ────────────────────────────────────────────────────────
    def emit(self, event: AnalysisEvent):
        """
        Synchronous emit — safe to call from non-async pipeline code.
        Puts event on all relevant queues without blocking.
        """
        payload = event.to_json()
        ev_dict = json.loads(payload)

        # Store in history
        hist = self._history[event.case_id]
        hist.append(ev_dict)
        if len(hist) > 200:
            hist.pop(0)

        # Push to case-specific subscribers
        for q in list(self._subscribers.get(event.case_id, set())):
            try:
                q.put_nowait(payload)
            except asyncio.QueueFull:
                pass  # Slow consumer — drop oldest

        # Push to global subscribers
        for q in list(self._global):
            try:
                q.put_nowait(payload)
            except asyncio.QueueFull:
                pass

    async def emit_async(self, event: AnalysisEvent):
        """Async emit — awaitable version."""
        self.emit(event)
        await asyncio.sleep(0)  # Yield control so subscribers can process

    def get_history(self, case_id: str) -> list[dict]:
        """Replay all events for a case (for late-joining WebSocket clients)."""
        return list(self._history.get(case_id, []))

    def clear_history(self, case_id: str):
        self._history.pop(case_id, None)

    def subscriber_count(self, case_id: str | None = None) -> int:
        if case_id:
            return len(self._subscribers.get(case_id, set()))
        return len(self._global)


# ── Global singleton ──────────────────────────────────────────────────────────
event_bus = EventBus()


# ── Helper emitters ───────────────────────────────────────────────────────────
def emit(event_type: EventType, case_id: str, data: dict = None,
         severity: str = "INFO"):
    """Quick helper — emit an event from anywhere in the codebase."""
    event_bus.emit(AnalysisEvent(event_type, case_id, data, severity))


def emit_finding(case_id: str, engine: str, severity: str,
                 title: str, description: str, score: int = 0,
                 mitre: str = ""):
    """Emit a single security finding event."""
    emit(EventType.STATIC_FINDING, case_id, {
        "engine"     : engine,
        "title"      : title,
        "description": description,
        "score"      : score,
        "mitre"      : mitre,
    }, severity=severity)


def emit_score_update(case_id: str, dimension: str, raw: float,
                      contribution: float, total_so_far: float):
    """Emit a risk score dimension update (fires once per dimension)."""
    emit(EventType.SCORE_UPDATE, case_id, {
        "dimension"      : dimension,
        "raw"            : round(raw, 1),
        "contribution"   : round(contribution, 2),
        "total_so_far"   : round(total_so_far, 1),
    })


def emit_yara_match(case_id: str, rule_id: str, family: str,
                    severity: str, weight: int):
    """Emit a YARA rule match event."""
    emit(EventType.YARA_MATCH, case_id, {
        "rule_id" : rule_id,
        "family"  : family,
        "weight"  : weight,
    }, severity=severity)
