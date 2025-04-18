from fastapi import FastAPI
from app.auth import router as auth_router  # This should work if router is correctly defined in app/auth.py

app = FastAPI()

# Include the authentication router
app.include_router(auth_router, prefix="/auth", tags=["auth"])

@app.get("/")
async def root():
    return {"message": "Welcome to FastAPI!"}

