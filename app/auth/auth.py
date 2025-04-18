from datetime import datetime, timedelta
from dotenv import load_dotenv
from fastapi import APIRouter, HTTPException
from jose import jwt
from pydantic import BaseModel
import requests
import os
from passlib.context import CryptContext
from typing import Optional

load_dotenv()

# Initialize FastAPI router
router = APIRouter()

# Hasura settings
HASURA_GRAPHQL_API_CREATE_USER = os.getenv("HASURA_GRAPHQL_API_CREATE_USER")
HASURA_GRAPHQL_API_CHECK_USER = os.getenv("HASURA_GRAPHQL_API_CHECK_USER",)
HASURA_ADMIN_SECRET = os.getenv("HASURA_ADMIN_SECRET")
ACCESS_TOKEN_EXPIRE_MINUTES = 30
JWT_SECRET_KEY  = os.getenv("JWT_SECRET_KEY")
ALGORITHM = "HS256"

# Password hashing settings
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Pydantic schemas
class UserRegister(BaseModel):
    email: str
    password: str
    name: str

class UserLogin(BaseModel):
    email: str
    password: str
    

class UserInDB(UserRegister):
    password: str

# Helper function for password hashing
def get_password_hash(password: str):
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password:str):
    return pwd_context.verify(plain_password, hashed_password)

# Function to check if user already exists using GET with query param
def check_if_user_exists(email: str):
    headers = {
        'x-hasura-admin-secret': HASURA_ADMIN_SECRET,
    }

    response = requests.post(HASURA_GRAPHQL_API_CHECK_USER, headers=headers, json={"email": email})
    
    if response.status_code == 200:
        data = response.json()
        users = data.get("users", [])
        return len(users) > 0  # True if user exists, False otherwise
    
    raise HTTPException(status_code=500, detail="Error checking user existence in Hasura")

def fetch_user_data(email: str):
    headers = {
        'x-hasura-admin-secret': HASURA_ADMIN_SECRET,
    }
    response = requests.post(HASURA_GRAPHQL_API_CHECK_USER, headers=headers, json={"email": email})
    if response.status_code == 200:
        data = response.json()
        users = data.get("users", [])
        return users[0] if users else None
    raise HTTPException(status_code=500, detail="Error fetching user")


# Function to create a new user
def create_user_in_hasura(user_data: UserInDB):
    headers = {
        'x-hasura-admin-secret': HASURA_ADMIN_SECRET,
        'Content-Type': 'application/json'
    }
    response = requests.post(HASURA_GRAPHQL_API_CREATE_USER, json={
        "email": user_data.email,
        "password": user_data.password,
        "name": user_data.name
    }, headers=headers)

    if response.status_code != 200:
        raise HTTPException(status_code=500, detail="Error creating user in Hasura")

    return response.json()

# Register route
@router.post("/register")
async def register(user: UserRegister):
    user_exists = check_if_user_exists(user.email)
    
    if user_exists:
        raise HTTPException(status_code=400, detail="User is already registered")

    hashed_password = get_password_hash(user.password)
    new_user = UserInDB(email=user.email, name=user.name, password=hashed_password)

    created_user = create_user_in_hasura(new_user)

    return {"message": "User created successfully", "user": created_user}

@router.post("/login")
async def login(user: UserLogin):
    user_data = fetch_user_data(user.email)

    if not user_data:
        raise HTTPException(status_code=400, detail="User not registered")

    hashed_password = user_data.get("password")
    if not verify_password(user.password, hashed_password):
        raise HTTPException(status_code=401, detail="Incorrect password")

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode = {
        "sub": user.email,
        "exp": datetime.utcnow() + access_token_expires
    }
    access_token = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=ALGORITHM)

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "id": user_data.get("id"),
            "email": user_data.get("email"),
            "name": user_data.get("name"),
        }
    }
