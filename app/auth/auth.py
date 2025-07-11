from datetime import datetime, timedelta
from typing import List
from dotenv import load_dotenv
from fastapi import APIRouter, File, UploadFile, HTTPException, Request
from jose import jwt
from jose.exceptions import JWTError
from pydantic import BaseModel
import requests
import httpx
import os
from passlib.context import CryptContext
from fastapi.responses import JSONResponse
from ..utils.email import send_reset_email
from cloudinary.uploader import upload
from cloudinary.exceptions import Error

load_dotenv()

# Initialize FastAPI router
router = APIRouter()

# Hasura settings
HASURA_GRAPHQL_API_CREATE_USER = os.getenv("HASURA_GRAPHQL_API_CREATE_USER")
HASURA_GRAPHQL_API_CHECK_USER = os.getenv("HASURA_GRAPHQL_API_CHECK_USER")
HASURA_GRAPHQL_API_RESET_PASSWORD = os.getenv("HASURA_GRAPHQL_API_RESET_PASSWORD")
HASURA_GRAPHQL_API_UPDATE_USER = os.getenv("HASURA_GRAPHQL_API_UPDATE_USER")
HASURA_GRAPHQL_API_GET_USER_DATA = os.getenv("HASURA_GRAPHQL_API_GET_USER_DATA")
HASURA_GRAPHQL_API_SAVE_IMAGE_URL = os.getenv("HASURA_GRAPHQL_API_SAVE_IMAGE_URL")


HASURA_ADMIN_SECRET = os.getenv("HASURA_ADMIN_SECRET")
ACCESS_TOKEN_EXPIRE_MINUTES = 30
JWT_SECRET_KEY  = os.getenv("JWT_SECRET_KEY")
ALGORITHM = "HS256"
FRONTEND_URL = os.getenv("FRONTEND_URL")


# Password hashing settings
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Pydantic schemas
class UserRegister(BaseModel):
    email: str
    password: str
    name: str

class SkillItem(BaseModel):
    skill_id: str

class SkillCreatePayload(BaseModel):
    skills: List[SkillItem]
    age: int
    occupation: str
    gender: str
    location: str
    bio: str

class PasswordResetCheck(BaseModel):
    email: str
class UserLogin(BaseModel):
    email: str
    password: str
    
class UserInDB(UserRegister):
    password: str

class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str

# Helper function for password hashing
def get_password_hash(password: str):
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password:str):
    return pwd_context.verify(plain_password, hashed_password)

# Function to save the user profile image url to the db
def save_profile_image(url: str, user_email: str):
    headers = {
        'x-hasura-admin-secret': HASURA_ADMIN_SECRET,
        'Content-Type': 'application/json'
    }
    payload = {
        "email": user_email,
        "profile_picture": url
    }

    
    response = requests.post(HASURA_GRAPHQL_API_SAVE_IMAGE_URL, json=payload, headers=headers)
    

    if response.status_code != 200:
        raise HTTPException(status_code=500, detail="Error saving profile image URL to Hasura")
    
    return response.json()


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

# Helper function to retrieve user from the data, necessary for login
# TODO refactor check_if_user_exists and fetch_user_data together

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

# Function to update the password

def update_password_in_hasura(email: str, hashed_password: str):
    headers = {
        "x-hasura-admin-secret": HASURA_ADMIN_SECRET,
        "Content-Type": "application/json"
    }
    payload = {
        "email": email,
        "new_password": hashed_password
    }
    response = requests.post(HASURA_GRAPHQL_API_RESET_PASSWORD, json=payload, headers=headers)
    if response.status_code != 200:
        raise HTTPException(status_code=500, detail="Failed to update password in Hasura")

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

@router.post("/register", operation_id="custom_register_user")
async def register(user: UserRegister):
    user_exists = check_if_user_exists(user.email)
    
    if user_exists:
        raise HTTPException(status_code=400, detail="User is already registered")

    hashed_password = get_password_hash(user.password)
    new_user = UserInDB(email=user.email, name=user.name, password=hashed_password)

    created_user = create_user_in_hasura(new_user)

    return {"message": "User created successfully", "user": created_user}

# Login

@router.post("/login", operation_id="custom_user_login")
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

    response = JSONResponse(content={
        "message": "Login successful",
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "id": user_data.get("id"),
            "email": user_data.get("email"),
            "name": user_data.get("name"),
        }
    })

    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        samesite="lax",
        secure=False,  # change to True when in HTTPS production
        path="/"
    )

    return response

# Update profile

@router.post("/update-profile", operation_id="custom_update_user_profile")
async def update_profile(request: Request, payload: SkillCreatePayload):
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=401, detail="Missing authentication token")

    try:
        decoded_payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[ALGORITHM])
        email = decoded_payload.get("sub")
        if not email:
            raise HTTPException(status_code=400, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    # Get user ID from Hasura
    user = fetch_user_data(email)
    user_id = user.get("id")

    # Build the skill objects list
    skill_objects = [
        {"user_id": user_id, "skill_id": skill.skill_id}
        for skill in payload.skills
    ]

    # Build the JSON body expected by Hasura REST endpoint
    hasura_payload = {
        "userId": user_id,
        "age": payload.age,
        "occupation": payload.occupation,
        "gender": payload.gender,
        "location": payload.location,
        "bio": payload.bio,
        "skillObjects": skill_objects
    }

    headers = {
        "x-hasura-admin-secret": HASURA_ADMIN_SECRET,
        "Content-Type": "application/json"
    }

    response = requests.post(HASURA_GRAPHQL_API_UPDATE_USER, json=hasura_payload, headers=headers)

    if response.status_code != 200:
        raise HTTPException(status_code=500, detail=f"Failed to update profile: {response.text}")

    return {"message": "Profile and skills updated successfully"}

#Get user data

@router.post("/get-user-data", operation_id="custom_user_data_retrieval")
async def get_user_data(request: Request): 
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=401, detail="Missing authentication token")
    
    try:
        decoded_payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[ALGORITHM])
        email = decoded_payload.get("sub")
        if not email:
            raise HTTPException(status_code=400, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    
    user = fetch_user_data(email)
    user_id = user.get("id")

    hasura_payload = {
        "userId" : user_id
    }

    headers = {
        "x-hasura-admin-secret": HASURA_ADMIN_SECRET,
        "Content-Type": "application/json"
    }

    async with httpx.AsyncClient() as client:
        response = await client.post(HASURA_GRAPHQL_API_GET_USER_DATA, json=hasura_payload, headers=headers)

    return response.json()
    

# Reset password

@router.post("/reset-password", operation_id="custom_user_reset_password")
async def reset_password(request: ResetPasswordRequest):
    try:
        # 1. Decode token
        payload = jwt.decode(request.token, JWT_SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if not email:
            raise HTTPException(status_code=400, detail="Invalid token")
        
        # 2. Hash new password
        hashed_password = pwd_context.hash(request.new_password)

        # 3. Call Hasura mutation
        headers = {
            "x-hasura-admin-secret": HASURA_ADMIN_SECRET,
            "Content-Type": "application/json"
        }
        data = {
            "email": email,
            "password": hashed_password
        }
        response = requests.post(HASURA_GRAPHQL_API_RESET_PASSWORD, json=data, headers=headers)

        if response.status_code != 200:
            raise HTTPException(status_code=500, detail="Failed to update password in Hasura")

        return {"message": "Password updated successfully"}

    except JWTError:
        raise HTTPException(status_code=400, detail="Invalid or expired token")




@router.post("/reset-password-link", operation_id="custom_send_password_reset_link")
async def send_reset_password_link (request: PasswordResetCheck):
    check_user = check_if_user_exists(request.email)

    if check_user is None or check_user == {}:
        raise HTTPException(status_code=404, detail="User is not registered")
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode = {
        "sub": request.email,
        "exp": datetime.utcnow() + access_token_expires
    }

    access_token = jwt.encode(to_encode, JWT_SECRET_KEY ,algorithm=ALGORITHM)

    reset_link = f"{FRONTEND_URL}/reset-password?token={access_token}"

    # Send the email using your utility
    send_reset_email(to_email=request.email, reset_link=reset_link)

    return JSONResponse(content={
        "status": "success",
        "message": f"Reset password email sent to {request.email}"
    })


# Image upload router
@router.post("/upload-profile-image", operation_id="custom_upload_user_profile_image")
async def upload_profile_image(request: Request, file: UploadFile = File(...)):
    token = request.cookies.get("access_token")

    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")

    decoded_payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[ALGORITHM])

    email = decoded_payload.get("sub")

    try:
        result = upload(file.file, folder="profiles", public_id=file.filename.split('.')[0])

        image_url = result["secure_url"]
        try:
            save_profile_image(image_url, email)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to save image: {str(e)}")
        return JSONResponse(content={
        "status": "success",
        "message": f"Image Uploaded, url: {image_url}"
    })
    except Error as e:
        raise HTTPException(status_code=500, detail=str(e))