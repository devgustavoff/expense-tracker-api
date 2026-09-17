from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel
from sqlmodel import Session, SQLModel, create_engine, Field
from datetime import datetime, timezone
from decimal import Decimal
from sqlalchemy.exc import IntegrityError
from pwdlib import PasswordHash

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

def verify_password(plain_password, hashed_password):
    return password_hash.verify(plain_password, hashed_password)

def get_password_hash(password):
    return password_hash.hash(password)

app = FastAPI()

@app.post("/users", response_model=UserOut)
async def create_user(*, session: Session = Depends(get_session), user: UserIn) -> User:
    new_user = User(username=user.username, password=get_password_hash(user.password))
    session.add(new_user)
    try:
        session.commit()
    except IntegrityError:
        session.rollback()
        raise HTTPException(status_code=400, detail="Username already exists")
    session.refresh(new_user)
    return new_user