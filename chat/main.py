import logging
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Query, status
from jose import jwt, JWTError
from typing import List, Dict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI()

SECRET_KEY = "my_secret_key"
ALGORITHM = "HS256"


class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, List[WebSocket]] = {}

    async def connect(self, room_id: str, websocket: WebSocket):
        await websocket.accept()
        if room_id not in self.active_connections:
            self.active_connections[room_id] = []
        self.active_connections[room_id].append(websocket)

    def disconnect(self, room_id: str, websocket: WebSocket):
        self.active_connections[room_id].remove(websocket)
        if not self.active_connections[room_id]:
            del self.active_connections[room_id]

    async def broadcast(self, room_id: str, message: str):
        for connection in self.active_connections.get(room_id, []):
            await connection.send_text(message)


manager = ConnectionManager()


async def authenticate_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_email = payload.get("sub")
        room_id = payload.get("room_id")
        room_name = payload.get("room_name")

        logger.info(f"Decoded JWT Payload - user_email: {user_email}, room_id: {room_id}, room_name: {room_name}")

        if not user_email or not room_id:
            logger.error("Invalid token payload: missing user_email or room_id")
            raise JWTError("Invalid token payload")

        return user_email, room_id, room_name
    except JWTError as e:
        logger.error(f"JWTError: {e}")
        return None


@app.websocket("/ws/chat/{chat_room_id}")
async def websocket_endpoint(websocket: WebSocket, chat_room_id: str, token: str = Query(...)):
    logger.info(f"Received WebSocket connection request for room_id: {chat_room_id} with token: {token}")

    auth_data = await authenticate_token(token)
    if auth_data is None:
        logger.error("Authentication failed: Invalid token")
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    user_email, room_id, room_name = auth_data
    logger.info(f"Token room_id: {room_id}, Requested room_id: {chat_room_id}")

    if str(room_id) != chat_room_id:
        logger.error("Room ID mismatch")
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await manager.connect(chat_room_id, websocket)
    await manager.broadcast(chat_room_id, f"Пользователь {user_email} подключился к комнате {room_name}.")

    try:
        while True:
            data = await websocket.receive_text()
            await manager.broadcast(chat_room_id, f"{user_email}: {data}")
    except WebSocketDisconnect:
        manager.disconnect(chat_room_id, websocket)
        await manager.broadcast(chat_room_id, f"Пользователь {user_email} покинул комнату {room_name}.")
