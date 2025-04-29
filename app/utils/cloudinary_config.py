import cloudinary
import cloudinary.uploader
import os 
from dotenv import load_dotenv

load_dotenv()


CLOUDINARY_API_KEY= os.getenv("CLOUDINARY_API_KEY")
CLOUDINARY_API_SECRET = os.getenv("CLOUDINARY_API_SECRET")
CLOUDINARY_CLOUD_NAME= os.getenv("CLOUDINARY_CLOUD_NAME")

cloudinary.config(
    cloud_name=CLOUDINARY_CLOUD_NAME,
    api_key=CLOUDINARY_API_KEY,
    api_secret=CLOUDINARY_API_SECRET,
    secure=True
)