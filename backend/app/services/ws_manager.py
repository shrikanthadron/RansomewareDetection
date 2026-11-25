"""WebSocket connection manager for real-time monitoring, training progress, and alerts."""

import asyncio
from typing import Any, Dict, Set
from fastapi import WebSocket


class ConnectionManager:
    def __init__(self) -> None:
        self._connections: Set[WebSocket] = set()
        self._loop: asyncio.AbstractEventLoop | None = None

    def set_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self._connections.add(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        self._connections.discard(websocket)

    async def broadcast(self, message: Dict[str, Any]) -> None:
        dead: list[WebSocket] = []
        for conn in list(self._connections):
            try:
                await conn.send_json(message)
            except Exception:
                dead.append(conn)
        for conn in dead:
            self._connections.discard(conn)

    def broadcast_threadsafe(self, message: Dict[str, Any]) -> None:
        if self._loop and self._loop.is_running() and self._connections:
            asyncio.run_coroutine_threadsafe(self.broadcast(message), self._loop)


ws_manager = ConnectionManager()
