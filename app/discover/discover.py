import httpx
from fastapi import HTTPException, status, APIRouter
from jose import jwt, JWTError
from starlette.requests import Request
from dotenv import load_dotenv
import os
from app.auth.auth import JWT_SECRET_KEY, ALGORITHM, HASURA_ADMIN_SECRET
import requests


router = APIRouter()
load_dotenv()

HASURA_GRAPHQL_API_GET_ALL_USER = os.getenv("HASURA_GRAPHQL_API_GET_ALL_USER")
HASURA_GRAPHQL_API_GET_ALL_DATA = os.getenv("HASURA_GRAPHQL_API_GET_ALL")

#Helper function
def get_all_users():
    headers = {
        'x-hasura-admin-secret': HASURA_ADMIN_SECRET,
    }
    response = requests.post(HASURA_GRAPHQL_API_GET_ALL_DATA, headers=headers)
    if response.status_code == 200:
        data = response.json()
        return data["users"]

    raise HTTPException(status_code=500, detail="Error fetching users")

# Function to handle token decoding and validation
def decode_jwt_token(token: str):
    try:
        decode_payload = jwt.decode(token, JWT_SECRET_KEY, [ALGORITHM])
        email = decode_payload.get("sub")
        if not email:
            raise HTTPException(status_code=400, detail="Invalid token: No email found")
        return email
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")


# Function to call the Hasura GraphQL API
async def fetch_users_from_hasura(exclude_email: str):
    payload = {"excludeEmail": exclude_email}
    headers = {
        "x-hasura-admin-secret": HASURA_ADMIN_SECRET,
        "Content-Type": "application/json"
    }

    async with httpx.AsyncClient() as client:
        response = await client.post(HASURA_GRAPHQL_API_GET_ALL_USER, json=payload, headers=headers)

        if response.status_code != 200:
            raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Error fetching users from Hasura")

        return response.json()


# Get all users
@router.post("/discover", operation_id="custom_discover_users")
async def discover(request: Request):
    token = request.cookies.get("access_token")

    if not token:
        # If no token, return all users (without exclusion)
        users = get_all_users()
        return {"users": users}

    # Decode the token and get the email
    email = decode_jwt_token(token)

    # Fetch users from Hasura excluding the logged-in user
    users = await fetch_users_from_hasura(email)

    return {"users": users}
