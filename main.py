from fastapi import FastAPI
from app.auth import router as auth_router
from app.match import router as match_router
from app.discover import router as discover_router
from fastapi.middleware.cors import CORSMiddleware
import os
from dotenv import load_dotenv

load_dotenv()

FRONTEND_URL = os.getenv("FRONTEND_URL")

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_URL],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include the authentication router
app.include_router(auth_router, prefix="/auth", tags=["auth"])
app.include_router(match_router, tags=["match"])
app.include_router(discover_router, tags=["discover"])

@app.get("/")
async def root():
    return {"message": "Welcome to FastAPI!"}

