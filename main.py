from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel
from sqlmodel import Session, SQLModel, create_engine, Field, select
from datetime import datetime, timezone, timedelta
from decimal import Decimal
from sqlalchemy.exc import IntegrityError
from pwdlib import PasswordHash
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import jwt
from jwt.exceptions import InvalidTokenError
from typing import Annotated

SECRET_KEY = "4081ba4c5e5fbdbdaaa415eb95bece4361aba25e2cb24b4c2adb3fa4f7f864a3"
ALGORITHM = "HS256"

def current_timestamp():
    return datetime.now(timezone.utc)

class User(SQLModel, table=True):
    __tablename__ = "users"

    user_id: int | None = Field(default=None, primary_key=True)
    username: str = Field(max_length=50, unique=True)
    password: str = Field(max_length=255)
    created_at: datetime = Field(default_factory=current_timestamp)
    last_login: datetime | None = Field(default=None)

class Expense(SQLModel, table=True):
    __tablename__ = "expenses"

    expense_id: int | None = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="users.user_id")
    amount: Decimal = Field(max_digits=10, decimal_places=2) 
    description: str 
    category: str | None = Field(default=None)
    created_at: datetime = Field(default_factory=current_timestamp)

engine = create_engine("postgresql://app:secret@db:5432/expense-tracker")

class UserOut(BaseModel):
    username: str

class UserIn(UserOut):
    password: str

def get_session():
    with Session(engine) as session:
        yield session

password_hash = PasswordHash.recommended()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def verify_password(plain_password, hashed_password):
    return password_hash.verify(plain_password, hashed_password)

def get_password_hash(password):
    return password_hash.hash(password)

def get_current_user(*, session: Session = Depends(get_session), token: str = Depends(oauth2_scheme)):
    payload = decode_access_token(token=token)
    statement = select(User).where(User.username == payload.get("sub"))
    user = session.exec(statement=statement).first()
    if user is None:
        raise HTTPException(status_code=401, detail="User not exists.")
    return user

def decode_access_token(token:str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token invalid or expired")
    return payload

app = FastAPI()

@app.post("/singup", response_model=UserOut)
async def create_user(*, session: Session = Depends(get_session), user: UserIn) -> User:
    new_user = User(username=user.username, password=get_password_hash(user.password))
    session.add(new_user)
    try:
        session.commit()
    except IntegrityError:
        session.rollback()
        raise HTTPException(status_code=400, detail="Username already exists.")
    session.refresh(new_user)
    return new_user

@app.post("/login")
async def login(*, session: Session = Depends(get_session), form_data: OAuth2PasswordRequestForm = Depends()):
    expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode = {
        "sub": form_data.username,
        "exp": expire
        }
    statement = select(User).where(User.username == form_data.username)
    user_db = session.exec(statement=statement).first()
    if user_db is None:
        raise HTTPException(status_code=404, detail="Username not exists.")
    if not verify_password(form_data.password, user_db.password):
        raise HTTPException(status_code=401, detail="Password wrong")

    access_token = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/me", response_model_exclude={"password"})
async def me(current_user: User = Depends(get_current_user)) -> User:
    return current_user