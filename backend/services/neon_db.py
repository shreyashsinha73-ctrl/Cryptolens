import os
import json
import logging
from typing import Optional, Dict, Any
from dotenv import load_dotenv
import psycopg2
from psycopg2.extras import Json

load_dotenv()
logger = logging.getLogger(__name__)

def get_connection():
    db_url = os.getenv("DATABASE_URL")
    if not db_url:
        return None
    try:
        return psycopg2.connect(db_url)
    except Exception as e:
        logger.warning(f"[!] Neon connection error: {e}")
        return None

def init_neon_tables():
    """Ensure required tables exist in Neon Postgres."""
    conn = get_connection()
    if not conn:
        return False
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS generated_reports (
                        job_id VARCHAR(64) NOT NULL,
                        report_type VARCHAR(32) NOT NULL,
                        pdf_data BYTEA NOT NULL,
                        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                        PRIMARY KEY (job_id, report_type)
                    );
                    CREATE TABLE IF NOT EXISTS analysis_results (
                        job_id VARCHAR(64) PRIMARY KEY,
                        result_data JSONB NOT NULL,
                        status VARCHAR(32) DEFAULT 'completed',
                        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
                    );
                    CREATE INDEX IF NOT EXISTS idx_reports_job ON generated_reports (job_id);
                """)
        return True
    except Exception as e:
        logger.warning(f"[!] Neon init tables error: {e}")
        return False
    finally:
        conn.close()

def save_pdf_to_neon(job_id: str, report_type: str, pdf_bytes: bytes) -> bool:
    conn = get_connection()
    if not conn:
        return False
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO generated_reports (job_id, report_type, pdf_data)
                    VALUES (%s, %s, %s)
                    ON CONFLICT (job_id, report_type) 
                    DO UPDATE SET pdf_data = EXCLUDED.pdf_data, created_at = NOW();
                """, (job_id, report_type.lower(), psycopg2.Binary(pdf_bytes)))
        return True
    except Exception as e:
        logger.warning(f"[!] Neon PDF save error: {e}")
        return False
    finally:
        conn.close()

def get_pdf_from_neon(job_id: str, report_type: str) -> Optional[bytes]:
    conn = get_connection()
    if not conn:
        return None
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT pdf_data FROM generated_reports 
                    WHERE job_id = %s AND report_type = %s;
                """, (job_id, report_type.lower()))
                row = cur.fetchone()
                return bytes(row[0]) if row else None
    except Exception as e:
        logger.warning(f"[!] Neon PDF fetch error: {e}")
        return None
    finally:
        conn.close()

def save_analysis_result_to_neon(job_id: str, result: Dict[str, Any], status: str = "completed") -> bool:
    conn = get_connection()
    if not conn:
        return False
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO analysis_results (job_id, result_data, status)
                    VALUES (%s, %s, %s)
                    ON CONFLICT (job_id) 
                    DO UPDATE SET result_data = EXCLUDED.result_data, status = EXCLUDED.status, created_at = NOW();
                """, (job_id, Json(result), status))
        return True
    except Exception as e:
        logger.warning(f"[!] Neon analysis result save error: {e}")
        return False
    finally:
        conn.close()

def get_analysis_result_from_neon(job_id: str) -> Optional[Dict[str, Any]]:
    conn = get_connection()
    if not conn:
        return None
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT result_data FROM analysis_results 
                    WHERE job_id = %s;
                """, (job_id,))
                row = cur.fetchone()
                if row and row[0]:
                    data = row[0]
                    if isinstance(data, str):
                        data = json.loads(data)
                    return data
                return None
    except Exception as e:
        logger.warning(f"[!] Neon analysis result fetch error: {e}")
        return None
    finally:
        conn.close()

def exists_in_neon(job_id: str) -> bool:
    conn = get_connection()
    if not conn:
        return False
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1 FROM analysis_results WHERE job_id = %s LIMIT 1;", (job_id,))
                return cur.fetchone() is not None
    except Exception:
        return False
    finally:
        conn.close()