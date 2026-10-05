import os
from typing import Optional
from dotenv import load_dotenv
import psycopg2
from psycopg2.extras import Json

load_dotenv()

def get_connection():
    db_url = os.getenv("DATABASE_URL")
    if not db_url:
        return None
    return psycopg2.connect(db_url)

def save_pdf_to_neon(job_id: str, report_type: str, pdf_bytes: bytes) -> bool:
    try:
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO generated_reports (job_id, report_type, pdf_data)
                    VALUES (%s, %s, %s)
                    ON CONFLICT (job_id, report_type) 
                    DO UPDATE SET pdf_data = EXCLUDED.pdf_data, created_at = NOW();
                """, (job_id, report_type.lower(), psycopg2.Binary(pdf_bytes)))
                conn.commit()
                return True
    except Exception as e:
        print(f"[!] Neon PDF save error: {e}")
        return False

def get_pdf_from_neon(job_id: str, report_type: str) -> Optional[bytes]:
    try:
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT pdf_data FROM generated_reports 
                    WHERE job_id = %s AND report_type = %s;
                """, (job_id, report_type.lower()))
                row = cur.fetchone()
                return bytes(row[0]) if row else None
    except Exception as e:
        print(f"[!] Neon PDF fetch error: {e}")
        return None