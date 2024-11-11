from datetime import datetime, timedelta, timezone
from http.cookies import SimpleCookie
from typing import Optional
from fastapi import FastAPI, Depends, HTTPException, APIRouter
from fastapi import Request, Form
from fastapi import status
from fastapi.responses import HTMLResponse
from fastapi.responses import RedirectResponse
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from fastapi.templating import Jinja2Templates
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session
import database
from database import get_db
from models.chat_room import ChatRoom
from models.user import User, Base
from pydantic import BaseModel

templates = Jinja2Templates(directory="templates")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

Base.metadata.create_all(bind=database.engine)

app = FastAPI()

router = APIRouter()
app.include_router(router)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

SECRET_KEY = "my_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


def get_password_hash(password):
    return pwd_context.hash(password)


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()

    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)

    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


class UserCreate(BaseModel):
    email: str
    password: str


async def get_current_user(request: Request, db: Session = Depends(get_db)):

    token = request.headers.get("Authorization")
    if token and token.startswith("Bearer "):
        token = token[len("Bearer "):]
    elif "Authorization" in request.cookies:
        token = request.cookies.get("Authorization").strip('"')
        if token.startswith("Bearer "):
            token = token[len("Bearer "):]
    else:
        print("Токен не найден ни в заголовках, ни в cookie.")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            print("Не удалось извлечь email из токена.")
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

    try:
        user = db.query(User).filter(User.email == email).first()
    except Exception as e:
        print(f"Ошибка при подключении к базе данных: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database connection error",
        )

    if user is None:
        print(f"Пользователь с email {email} не найден в базе данных.")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not find user",
            headers={"WWW-Authenticate": "Bearer"},
        )

    print(f"Пользователь {user.email} аутентифицирован с токеном {token};")
    return user



@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request, db: Session = Depends(get_db)):
    user_is_authenticated = False
    user_email = ""

    try:
        user = await get_current_user(request, db)
        user_is_authenticated = True
        user_email = user.email
    except HTTPException as e:
        if e.status_code != 401:
            raise e

    return templates.TemplateResponse(
        "index.html",
        {"request": request, "user_is_authenticated": user_is_authenticated, "user_email": user_email},
    )


@app.get("/register", response_class=HTMLResponse)
async def get_register_page(request: Request, db: Session = Depends(get_db)):
    user_is_authenticated = False
    user_email = ""

    try:
        user = await get_current_user(request, db)
        user_is_authenticated = True
        user_email = user.email
    except HTTPException as e:
        if e.status_code != 401:
            raise e

    return templates.TemplateResponse(
        "register.html",
        {"request": request, "user_is_authenticated": user_is_authenticated, "user_email": user_email},
    )


@app.post("/register")
async def register_user(user: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    hashed_password = get_password_hash(user.password)
    new_user = User(email=user.email, hashed_password=hashed_password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return RedirectResponse(url="/login", status_code=303)


@app.get("/login", response_class=HTMLResponse)
async def get_login_page(request: Request, db: Session = Depends(get_db)):
    user_is_authenticated = False
    user_email = ""

    try:
        user = await get_current_user(request, db)
        user_is_authenticated = True
        user_email = user.email
    except HTTPException as e:
        if e.status_code != 401:
            raise e

    return templates.TemplateResponse(
        "login.html",
        {"request": request, "user_is_authenticated": user_is_authenticated, "user_email": user_email},
    )


@app.post("/login")
async def login_for_access_token(
        form_data: OAuth2PasswordRequestForm = Depends(),
        db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.email == form_data.username).first()
    print(f"Email check: {bool(user)}")
    print(f"Password check: {verify_password(form_data.password, user.hashed_password)}")
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )

    response = RedirectResponse(url="/chat_rooms", status_code=303)
    response.set_cookie(
        key="Authorization",
        value=f"Bearer {access_token}",
        httponly=False,
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        expires=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        secure=True,
        samesite="lax",
    )
    response.headers["Authorization"] = f"Bearer {access_token}"
    print(f"Bearer: {access_token}")
    return response


@app.get("/users/me")
async def read_users_me(current_user: User = Depends(get_current_user)):
    return {"email": current_user.email}


@app.post("/chat_rooms/")
async def create_chat_room(
        name: str = Form(...),
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    chat_room = db.query(ChatRoom).filter(ChatRoom.name == name).first()
    if chat_room:
        raise HTTPException(status_code=400, detail="Chat room with this name already exists")

    new_chat_room = ChatRoom(name=name, owner_id=current_user.id)
    db.add(new_chat_room)
    db.commit()
    db.refresh(new_chat_room)

    return {"message": f"Chat room '{name}' created successfully"}


@app.get("/chat_rooms", response_class=HTMLResponse)
async def get_chat_rooms(request: Request,
                         db: Session = Depends(get_db)):
    user_is_authenticated = False
    user_email = ""
    chat_rooms = []

    try:
        user = await get_current_user(request, db)
        user_is_authenticated = True
        chat_rooms = db.query(ChatRoom).filter(ChatRoom.owner_id == user.id).all()
        user_email = user.email
    except HTTPException as e:
        if e.status_code != 401:
            raise e

    return templates.TemplateResponse("chat_rooms.html",
                                      {"request": request, "user_is_authenticated": user_is_authenticated,
                                       "user_email": user_email, "chat_rooms": chat_rooms})


@app.delete("/chat_rooms/{room_id}")
async def delete_chat_room(room_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    chat_room = db.query(ChatRoom).filter(ChatRoom.id == room_id, ChatRoom.owner_id == current_user.id).first()
    if not chat_room:
        raise HTTPException(status_code=404, detail="Chat room not found or you do not have permission to delete it")

    db.delete(chat_room)
    db.commit()

    return {"message": f"Chat room '{chat_room.name}' deleted successfully"}


@app.get("/logout")
async def logout():
    response = RedirectResponse(url="/")

    response.delete_cookie(key="Authorization")
    response.delete_cookie(key="user")

    response.headers["Authorization"] = ""

    return response


@app.get("/chat/{room_id}", response_class=HTMLResponse)
async def enter_chat_room(
        room_id: int,
        request: Request,
        db: Session = Depends(get_db),
):
    user_is_authenticated = False
    user_email = ""
    try:
        user = await get_current_user(request, db)
        user_is_authenticated = True
        user_email = user.email
    except HTTPException as e:
        if e.status_code != 401:
            raise e
    chat_room = db.query(ChatRoom).filter(ChatRoom.id == room_id).first()
    print(chat_room)
    print(ChatRoom.id == room_id)
    if chat_room is None:
        raise HTTPException(status_code=404, detail="Chat room not found")

    return templates.TemplateResponse(
        "chat_room.html",
        {
            "request": request,
            "user_is_authenticated": user_is_authenticated,
            "user_email": user_email,
            "room_name": chat_room.name
        },
    )
