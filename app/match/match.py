import httpx
from fastapi import HTTPException, status
from jose import jwt, JWTError
from pydantic import BaseModel
from starlette.requests import Request
from starlette.responses import JSONResponse
from fastapi import APIRouter
import os
from dotenv import load_dotenv
from app.auth.auth import JWT_SECRET_KEY, ALGORITHM, HASURA_ADMIN_SECRET

load_dotenv()

HASURA_GRAPHQL_API_MATCH = os.getenv("HASURA_GRAPHQL_API_MATCH")
HASURA_GRAPHQL_API_UPDATE_MATCH = os.getenv("HASURA_GRAPHQL_API_UPDATE_MATCH")
HASURA_GRAPHQL_API_GET_ALL_MATCHES = os.getenv("HASURA_GRAPHQL_API_GET_ALL_MATCHES")
HASURA_GRAPHQL_API_IS_MATCHED = os.getenv("HASURA_GRAPHQL_API_IS_MATCHED")

# Initialize FastAPI router
router = APIRouter()

#Pydantic
class IsMatchedPayload(BaseModel):
    email2: str

class MatchPayload(BaseModel):
    email_to_match: str

class UpdateStatusPayload(BaseModel):
    user2_email: str
    status: str

# Helper function to decode JWT and get email
def decode_jwt_token(token: str):
    try:
        decoded_payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[ALGORITHM])
        email = decoded_payload.get("sub")
        if not email:
            raise HTTPException(status_code=400, detail="Invalid token: No email found")
        return email
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

# Match the user
@router.post("/match", operation_id="custom_match_user")
async def match_user(request: Request, payload: MatchPayload):
    token = request.cookies.get("access_token")

    if not token:
        raise HTTPException(status_code=401, detail="Not Authenticated")

    email = decode_jwt_token(token)

    json_payload = {
        "email1": email,
        "email2": payload.email_to_match
    }

    headers = {
        "x-hasura-admin-secret": HASURA_ADMIN_SECRET,
        "Content-Type": "application/json"
    }

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(HASURA_GRAPHQL_API_MATCH, json=json_payload, headers=headers)
            if response.status_code != 200:
                raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Failed to match users")
            return JSONResponse({"status": "success", "message": "Match created successfully"})
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=500, detail=f"HTTP error: {e}")

# Update Match Status
@router.post("/update-match", operation_id="custom_update_match_status")
async def update_match_status(request: Request, payload: UpdateStatusPayload):
    token = request.cookies.get("access_token")

    if not token:
        raise HTTPException(status_code=401, detail="Not Authenticated")

    email = decode_jwt_token(token)

    json_payload = {
        "email1": email,
        "email2": payload.user2_email,
        "status": payload.status
    }

    headers = {
        "x-hasura-admin-secret": HASURA_ADMIN_SECRET,
        "Content-Type": "application/json"
    }

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(HASURA_GRAPHQL_API_UPDATE_MATCH, json=json_payload, headers=headers)
            if response.status_code != 200:
                raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Failed to update match status")
            return JSONResponse({"status": "success", "message": "Match status updated successfully"})
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=500, detail=f"HTTP error: {e}")

# Get all matches
@router.post("/get-all-matches", operation_id="custom_get_all_matches")
async def get_all_matches(request: Request):
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=401, detail="Not Authorized")

    email = decode_jwt_token(token)

    payload = {
        "email": email
    }

    headers = {
        "x-hasura-admin-secret": HASURA_ADMIN_SECRET,
        "Content-Type": "application/json"
    }

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(HASURA_GRAPHQL_API_GET_ALL_MATCHES, json=payload, headers=headers)
            if response.status_code != 200:
                raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Failed to fetch matches")
            return response.json()
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=500, detail=f"HTTP error: {e}")

# Check if users are matched
@router.post("/is-matched", operation_id="custom_check_if_matched")
async def is_matched(request: Request, payload: IsMatchedPayload):
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=401, detail="Not Authenticated")

    email1 = decode_jwt_token(token)

    json_payload = {
        "email1": email1,
        "email2": payload.email2
    }

    headers = {
        "x-hasura-admin-secret": HASURA_ADMIN_SECRET,
        "Content-Type": "application/json"
    }

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(HASURA_GRAPHQL_API_IS_MATCHED, json=json_payload, headers=headers)
            if response.status_code != 200:
                raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Failed to check match status")
            data = response.json()
            count = data["data"]["matches_aggregate"]["aggregate"]["count"]
            return JSONResponse({"matched": count >= 1})
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=500, detail=f"HTTP error: {e}")
