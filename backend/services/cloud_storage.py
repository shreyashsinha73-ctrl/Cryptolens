import os
from typing import Optional
from dotenv import load_dotenv
import cloudinary
import cloudinary.uploader

load_dotenv()

def upload_capture_file(file_content: bytes, filename: str) -> Optional[str]:
    """Uploads capture/pcap to Cloudinary as raw asset and returns URL."""
    cloud_name = os.getenv("CLOUDINARY_CLOUD_NAME")
    api_key = os.getenv("CLOUDINARY_API_KEY")
    api_secret = os.getenv("CLOUDINARY_API_SECRET")

    if not (cloud_name and api_key and api_secret):
        print("[!] Cloudinary credentials missing in environment (.env). Skipping upload.")
        return None

    try:
        cloudinary.config(
            cloud_name=cloud_name,
            api_key=api_key,
            api_secret=api_secret,
            secure=True
        )
        res = cloudinary.uploader.upload(
            file_content,
            resource_type="raw",
            folder="cryptolens/captures",
            public_id=filename,
            overwrite=True
        )
        return res.get("secure_url")
    except Exception as exc:
        print(f"[!] Cloudinary upload error: {exc}")
        return None