from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel
from sqlmodel import Session, SQLModel, create_engine, Field, select, or_
from datetime import datetime, timezone, timedelta, date
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

class ExpenseIn(BaseModel):
    amount: Decimal
    description: str | None = None
    category: str | None = None

class ExpenseOut(BaseModel):
    expense_id: int
    amount: Decimal
    description: str
    category: str | None = None
    created_at: datetime

class ExpenseUpdate(BaseModel):
    amount: Decimal | None = None
    description: str | None = None
    category: str | None = None

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

@app.post("/expenses", response_model=ExpenseOut)
async def create_expense(*, session: Session = Depends(get_session), expense_data: ExpenseIn, current_user: User = Depends(get_current_user)) -> Expense:
    expense = Expense(
        user_id=current_user.user_id,
        amount=expense_data.amount,
        description=expense_data.description,
        category=expense_data.category
    )

    session.add(expense)
    session.commit()
    session.refresh(expense)

    return expense

@app.get("/expenses", response_model=list[ExpenseOut])
async def read_expenses(
    *, session: Session = Depends(get_session), 
    current_user: User = Depends(get_current_user), 
    category: str | None = None,
    start_date: date | None = None,
    end_date: date | None = None
    ) -> list[Expense]:

    statement = select(Expense).where(Expense.user_id == current_user.user_id)

    if category is not None:
        statement = statement.where(Expense.category == category)

    if start_date is not None:
        statement = statement.where(Expense.created_at >= start_date)

    if end_date is not None:
        statement = statement.where(Expense.created_at < end_date + timedelta(days=1))

    expenses = session.exec(statement).all()

    return list(expenses)

@app.get("/expenses/{expense_id}", response_model=ExpenseOut)
async def get_expense(expense_id: int, current_user: User = Depends(get_current_user), session: Session = Depends(get_session)):
    expense = session.get(Expense, expense_id)
    if expense is None:
        raise HTTPException(status_code=404, detail="Expense not found")

    if expense.user_id != current_user.user_id:
        raise HTTPException(status_code=403, detail="User not authorized")
    
    return expense

@app.patch("/expenses/{expense_id}", response_model=ExpenseUpdate)
async def update_expense(expense_id: int, client_datas: ExpenseUpdate, current_user: User = Depends(get_current_user), session: Session = Depends(get_session)):
    expense = session.get(Expense, expense_id)
    if expense is None:
        raise HTTPException(status_code=404, detail="Expense not found")

    if expense.user_id != current_user.user_id:
        raise HTTPException(status_code=401, detail="User not authorized")

    expense_data = client_datas.model_dump(exclude_unset=True)
    expense.sqlmodel_update(expense_data)
    session.add(expense)
    session.commit()
    session.refresh(expense)
    return expense

@app.delete("/expenses/{expense_id}", response_model=ExpenseOut)
async def delete_expense(expense_id: int, current_user: User = Depends(get_current_user), session: Session = Depends(get_session)):
    expense = session.get(Expense, expense_id)
    if expense is None:
        raise HTTPException(status_code=404, detail="Expense not found")

    if expense.user_id != current_user.user_id:
        raise HTTPException(status_code=401, detail="User not authorized")

    session.delete(expense)
    session.commit()

    return expense