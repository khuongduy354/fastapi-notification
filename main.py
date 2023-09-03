from datetime import datetime, timedelta
from typing import Annotated
from fastapi import FastAPI, WebSocket, Depends, Request, HTTPException, Query, WebSocketException, status
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from jose import JWTError, jwt

app = FastAPI()

# prepare
ACCESS_TOKEN_EXPIRE_MINUTES = 30
SECRET_KEY = "asdfasdf"
ALGORITHM = "HS256"
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
fake_microservices_db = {
    "2f8e214e8b2049d39dc8f7a4137789d2": {
        # TODO: here i auth microservice with uuid4 only, find other method to auth microservice
        "uuid4": "2f8e214e8b2049d39dc8f7a4137789d2",
        "name": "microservice1",

    }}
fake_users_db = {
    "2f8e214e8b2049d39dc8f7a4137789d2": {
        "uuid4": "2f8e214e8b2049d39dc8f7a4137789d2",
        "username": "user1",
        # TODO: hash this instead
        "password": "password1"
    }
}
# classes


class User(BaseModel):
    username: str
    password: str


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str
    uuid4: str
    password: str


@app.get("/")
def read_root():
    return {"Hello": "World"}


html = """
<!DOCTYPE html>
<html>
    <head>
        <title>Authorize</title>
    </head>
    <body>
        <h1>WebSocket Authorize</h1>
        <p>Token:</p>
        <textarea id="token" rows="4" cols="50"></textarea><br><br>
        <button onclick="websocketfun()">Send</button>
        <ul id='messages'>
        </ul>
        <script>
            const websocketfun = () => {
                let token = document.getElementById("token").value
                let ws = new WebSocket(`ws://192.168.18.202:8000/ws?token=${token}`)
                ws.onmessage = (event) => {
                    let messages = document.getElementById('messages')
                    let message = document.createElement('li')
                    let content = document.createTextNode(event.data)
                    message.appendChild(content)
                    messages.appendChild(message)
                }
            }
        </script>
    </body>
</html>
"""

# endpoints


@app.get("/")
async def get():
    return HTMLResponse(html)

# create token -> send token to ws -> ws validate token -> ws connect

# async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
#     credentials_exception = HTTPException(
#         status_code=status.HTTP_401_UNAUTHORIZED,
#         detail="Could not validate credentials",
#         headers={"WWW-Authenticate": "Bearer"},
#     )
#     try:
#         payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
#         user = payload.get("sub")
#         if user is None:
#             raise credentials_exception
#         token_data = TokenData(username=user.username,)
#     except JWTError:
#         raise credentials_exception
#     user = get_user(fake_users_db, username=token_data.username)
#     if user is None:
#         raise credentials_exception
#     return user


@app.websocket('/ws/notify')
async def notify_socket(websocket: WebSocket, token: Annotated[str, Depends(oauth2_scheme)], message: str):
    await websocket.accept()
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        micro = payload.get("sub")
        if micro is None:
            raise WebSocketException(code=403)
        # TODO: extract micro info
        await websocket.send_text(f"Here your decoded token: connected")
        # error
    except:
        await websocket.send_text("You are not authorized")
        await websocket.close()


@app.websocket('/ws')
async def websocket(websocket: WebSocket, token: Annotated[str, Depends(oauth2_scheme)]):
    await websocket.accept()
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user = payload.get("sub")
        if user is None:
            raise WebSocketException(code=403)
        # TODO: extract user info
        await websocket.send_text(f"Here your decoded token: connected")
        # error
    except:
        await websocket.send_text("You are not authorized")
        await websocket.close()


# @app.post('/login')
# def login(user: User, Authorize: AuthJWT = Depends()):
#     # authorize from username pass
#     if user.username != "test" or user.password != "test":
#         raise HTTPException(status_code=401, detail="Bad username or password")
#
#     # Create token
#     access_token = Authorize.create_access_token(
#         subject=user.username, fresh=True)
#     refresh_token = Authorize.create_refresh_token(subject=user.username)
#
#     # return token
#     return {"access_token": access_token, "refresh_token": refresh_token}

@app.post("/microservice/token", response_model=Token)
async def request_access_token(
        uuid4: str
):
    if uuid4 is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
        return
    micro = fake_microservices_db.get(uuid4)
    if not micro:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": micro}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.post("/token", response_model=Token)
async def login_for_access_token(
        user: User
):
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
        return
    user_result = authenticate_user(
        user.username, user.password, fake_users_db)
    if not user_result:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user_result}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

# helpers


def authenticate_user(username: str, password: str, db: dict):
    user = db.get(username)
    if user == None:
        return None
    elif user.password == password:
        return user
    return None


def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt
