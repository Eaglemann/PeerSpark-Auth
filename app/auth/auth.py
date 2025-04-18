from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
import requests
import os
from passlib.context import CryptContext
from typing import Optional

# Initialize FastAPI router
router = APIRouter()

# Hasura settings
HASURA_GRAPHQL_API_CREATE_USER = "https://peerspark.hasura.app/api/rest/createuser"
HASURA_GRAPHQL_API_CHECK_USER = "https://peerspark.hasura.app/api/rest/validateUser"
HASURA_ADMIN_SECRET = os.getenv("HASURA_ADMIN_SECRET", "5aSqI3SpqlprK04kVMmVpyHM5efcLZba6XcQ2wimiCAraPZYrPSzbxCCWqbEsjma")

# Password hashing settings
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Pydantic schemas
class UserRegister(BaseModel):
    email: str
    password: str
    name: str

class UserInDB(UserRegister):
    hashed_password: str

# Helper function for password hashing
def get_password_hash(password: str):
    return pwd_context.hash(password)

# Function to check if user already exists using GET with query param
def check_if_user_exists(email: str):
    headers = {
        'x-hasura-admin-secret': HASURA_ADMIN_SECRET,
    }
    params = {
        'email': email
    }
    response = requests.get(HASURA_GRAPHQL_API_CHECK_USER, headers=headers, params=params)
    
    if response.status_code == 200:
        data = response.json()
        users = data.get("users", [])
        return len(users) > 0  # True if user exists, False otherwise
    
    raise HTTPException(status_code=500, detail="Error checking user existence in Hasura")


# Function to create a new user
def create_user_in_hasura(user_data: UserInDB):
    headers = {
        'x-hasura-admin-secret': HASURA_ADMIN_SECRET,
        'Content-Type': 'application/json'
    }
    response = requests.post(HASURA_GRAPHQL_API_CREATE_USER, json={
        "email": user_data.email,
        "password": user_data.hashed_password,
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
    new_user = UserInDB(email=user.email, name=user.name, password=user.password, hashed_password=hashed_password)

    created_user = create_user_in_hasura(new_user)

    return {"message": "User created successfully", "user": created_user}
