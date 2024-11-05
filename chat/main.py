from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, HTTPException, status
from typing import List
from jose import jwt, JWTError
from models.user import User
from models.database import get_db
from sqlalchemy.orm import Session

app = FastAPI()

SECRET_KEY = "your-secret-key"  # Используйте тот же секретный ключ, что и в микросервисе website
ALGORITHM = "HS256"  # Используйте тот же алгоритм, что и в микросервисе website

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    async def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: str):
        for connection in self.active_connections:
            await connection.send_text(message)

manager = ConnectionManager()

async def get_current_user_ws(token: str, db: Session = Depends(get_db)):
    # Декодируем токен и извлекаем email
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
    except JWTError as e:
        print(f"Ошибка JWT при декодировании токена: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Проверяем наличие пользователя в базе данных
    user = db.query(User).filter(User.email == email).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not find user",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user



@app.websocket("/ws/chat/{chat_room_id}")
async def websocket_endpoint(websocket: WebSocket, chat_room_id: int, db: Session = Depends(get_db)):
    # Логируем получение токена
    print(f"Параметры запроса: {websocket.query_params}")
    token = websocket.query_params.get("token")

    if not token:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        print("Токен отсутствует. Соединение закрыто.")
        return

    if token.startswith("Bearer "):
        token = token[len("Bearer "):]

    # Проверяем авторизацию токена
    try:
        user = await get_current_user_ws(token, db)
        print(f"Пользователь {user.email} успешно подключился к комнате {chat_room_id}.")
    except HTTPException as e:
        print(f"Ошибка авторизации: {e.detail}")
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    # Подключаем пользователя
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            message = f"Пользователь {user.email} в комнате {chat_room_id} говорит: {data}"
            print(message)  # Логируем сообщение для отладки
            await manager.broadcast(message)
    except WebSocketDisconnect:
        await manager.disconnect(websocket)
        disconnect_message = f"Пользователь {user.email} покинул комнату {chat_room_id}."
        print(disconnect_message)
        await manager.broadcast(disconnect_message)
