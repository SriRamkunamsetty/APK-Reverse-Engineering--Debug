"""
RAKSHAK — WebSocket Real-Time Server
Streams every analysis event to connected dashboard clients as they happen.
Handles reconnection, history replay, and per-case subscriptions.
"""

import asyncio, json
from fastapi import WebSocket, WebSocketDisconnect
from core.event_bus import event_bus, EventType


class WebSocketManager:
    """Manages all active WebSocket connections with per-case routing"""

    def __init__(self):
        # case_id → list of (websocket, queue) tuples
        self._connections: dict[str, list[tuple]] = {}

    async def connect(self, ws: WebSocket, case_id: str | None = None):
        await ws.accept()
        q = event_bus.subscribe(case_id)

        if case_id not in self._connections:
            self._connections[case_id or "_global"] = []
        self._connections[case_id or "_global"].append((ws, q))

        # Replay history immediately so late joiners catch up
        if case_id:
            history = event_bus.get_history(case_id)
            for event in history:
                try:
                    await ws.send_text(json.dumps(event))
                except Exception:
                    break

        # Stream new events
        try:
            while True:
                try:
                    msg = await asyncio.wait_for(q.get(), timeout=30.0)
                    await ws.send_text(msg)
                except asyncio.TimeoutError:
                    # Send keepalive ping
                    await ws.send_text(json.dumps({"type": "ping"}))
        except (WebSocketDisconnect, Exception):
            pass
        finally:
            event_bus.unsubscribe(q, case_id)
            conns = self._connections.get(case_id or "_global", [])
            if (ws, q) in conns:
                conns.remove((ws, q))

    def active_count(self) -> int:
        return sum(len(v) for v in self._connections.values())


ws_manager = WebSocketManager()
