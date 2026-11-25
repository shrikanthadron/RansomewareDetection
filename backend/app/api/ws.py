"""WebSocket endpoint for real-time monitoring snapshots, training progress, and alerts."""

from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect
from app.core.security import decode_access_token
from app.services.ws_manager import ws_manager

router = APIRouter(tags=["WebSocket"])


@router.websocket("/ws/live")
async def websocket_live(websocket: WebSocket, token: str = Query(...)):
    payload = decode_access_token(token)
    if not payload:
        await websocket.close(code=1008)
        return

    await ws_manager.connect(websocket)
    try:
        await websocket.send_json({"type": "connected", "user_id": payload.get("sub")})
        while True:
            # Keep connection alive; ignore client pings or echo heartbeat
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_json({"type": "pong"})
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception:
        ws_manager.disconnect(websocket)
