
# CryptoLens Production Deployment & Cloud Integration Guide

This guide details the complete end-to-end setup for deploying **CryptoLens** to production across cloud services:

- **Frontend**: [Vercel](https://vercel.com) (React 19 + Vite SPA)
- **Backend**: [Render](https://render.com) (FastAPI + Python 3.11)
- **Database**: [Neon Postgres](https://neon.tech) (PDF reports & result persistence)
- **Media & File Storage**: [Cloudinary](https://cloudinary.com) (PCAP capture backups)
- **Uptime Monitoring**: [cron-job.org](https://cron-job.org) (Keeps Render free tier awake 24/7)

---

## 1. System Architecture

```mermaid
graph TD
    User([User Browser]) -->|Vite SPA / HTTPS| Vercel[Vercel Frontend]
    User -.->|Persists activeJobId| LocalStorage[(Browser LocalStorage)]
    Vercel -->|/api/v1/* Proxy / HTTPS| Render[Render Backend - FastAPI]
    
    Cron[cron-job.org] -->|Ping /health every 10 min| Render
    
    Render -->|Store / Load PDF & Results| Neon[(Neon Postgres DB)]
    Render -->|Backup PCAPs & Media| Cloudinary[(Cloudinary Cloud Storage)]
```

---

## 2. Pre-Deployment Code Adjustments

### A. Add Health Endpoint to Backend
Open `backend/main.py` and register a `/health` endpoint for Render and cron-job.org:

```python
@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "CryptoLens Core Analysis Engine",
        "version": "1.0.0"
    }
```

### B. Add Dependencies to `requirements.txt`
Ensure PostgreSQL and Cloudinary SDKs are listed in `requirements.txt`:

```text
psycopg2-binary>=2.9.9
cloudinary>=1.41.0
```

### C. Create `vercel.json` for SPA Routing & Reverse Proxy
In the root directory of the project, create `vercel.json`:

```json
{
  "rewrites": [
    {
      "source": "/api/:path*",
      "destination": "https://YOUR-RENDER-BACKEND.onrender.com/api/:path*"
    },
    {
      "source": "/(.*)",
      "destination": "/index.html"
    }
  ]
}
```

> [!TIP]
> This configuration handles both client-side React Router navigation (preventing 404s on page refresh) and routes all `/api/*` network requests directly to Render, avoiding browser CORS restrictions.

### D. Ensure Refresh Resilience in Frontend (`src/context/AppContext.jsx`)
To make sure data is not lost if the browser is refreshed mid-request or after analysis:

```javascript
// 1. Initialize activeJobId from localStorage
const [activeJobId, setActiveJobId] = useState(() => {
  return localStorage.getItem('cryptolens_active_job') || null;
});

// 2. Synchronize activeJobId changes to localStorage
useEffect(() => {
  if (activeJobId) {
    localStorage.setItem('cryptolens_active_job', activeJobId);
  } else {
    localStorage.removeItem('cryptolens_active_job');
  }
}, [activeJobId]);
```

---

## 3. Neon Postgres Database Setup

### Step 3.1: Create Neon Tables
1. Open your project on the [Neon Console](https://console.neon.tech).
2. Go to the **SQL Editor** tab in the sidebar.
3. Run the following DDL script:

```sql
-- Table to store generated PDF reports
CREATE TABLE IF NOT EXISTS generated_reports (
    job_id VARCHAR(64) NOT NULL,
    report_type VARCHAR(32) NOT NULL,
    pdf_data BYTEA NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    PRIMARY KEY (job_id, report_type)
);

-- Table to store analysis results for seamless reload
CREATE TABLE IF NOT EXISTS analysis_results (
    job_id VARCHAR(64) PRIMARY KEY,
    result_data JSONB NOT NULL,
    status VARCHAR(32) DEFAULT 'completed',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create lookup index for fast queries
CREATE INDEX IF NOT EXISTS idx_reports_job ON generated_reports (job_id);
```

### Step 3.2: Copy Connection String
In the Neon Dashboard, copy the connection URI:
```text
postgresql://neondb_owner:YOUR_PASSWORD@ep-xyz.eu-central-1.aws.neon.tech/neondb?sslmode=require
```

### Step 3.3: Neon Database Helper Module
Create `backend/services/neon_db.py`:

```python
import os
import psycopg2
from psycopg2.extras import Json

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

def get_pdf_from_neon(job_id: str, report_type: str) -> bytes | None:
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
```

---

## 4. Cloudinary Setup (Capture & Asset Cloud Storage)

Cloudinary stores uploaded `.pcap` files and binary assets so they survive server restarts.

### Step 4.1: Retrieve Cloudinary Credentials
1. Sign in to [Cloudinary](https://cloudinary.com/console).
2. From the **Dashboard**, copy:
   - **Cloud Name**
   - **API Key**
   - **API Secret**

### Step 4.2: Cloudinary Upload Helper Module
Create `backend/services/cloud_storage.py`:

```python
import os
import cloudinary
import cloudinary.uploader

cloudinary.config(
    cloud_name=os.getenv("CLOUDINARY_CLOUD_NAME"),
    api_key=os.getenv("CLOUDINARY_API_KEY"),
    api_secret=os.getenv("CLOUDINARY_API_SECRET"),
    secure=True
)

def upload_capture_file(file_content: bytes, filename: str) -> str | None:
    """Uploads capture/pcap to Cloudinary as raw asset and returns URL."""
    try:
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
```

---

## 5. Deploy Backend to Render

1. Log into [Render](https://dashboard.render.com).
2. Click **New +** → **Web Service**.
3. Select your GitHub repository (`CryptoLens`).
4. Configure service parameters:
   - **Name**: `cryptolens-backend`
   - **Environment**: `Python 3`
   - **Region**: Match your Neon region (e.g. `Frankfurt (EU Central)`).
   - **Branch**: `main`
   - **Build Command**:
     ```bash
     pip install -r requirements.txt
     ```
   - **Start Command**:
     ```bash
     uvicorn backend.main:app --host 0.0.0.0 --port $PORT
     ```
   - **Plan**: `Free`

5. Configure **Environment Variables** in Render:

   You can add environment variables either **during initial Web Service setup** or **anytime afterwards on an existing service**.

   #### Where to Find the Setting in Render:
   - **During Service Creation**: Scroll down to the bottom of the page to the **Environment Variables** section (if not visible, click **Advanced**).
   - **On an Existing Service**: Open [Render Dashboard](https://dashboard.render.com) → click on your Web Service (`cryptolens-backend`) → select the **Environment** tab in the left-hand sidebar navigation.

   #### How to Enter Variables:
   You have two options on Render:
   - **Option A — Bulk Add with `.env` (Recommended & Fastest)**:
     1. Click the **Add from .env** button.
     2. Paste the formatted environment block below directly into the text area.
     3. Replace placeholder values with your actual API keys and secrets.
     4. Click **Save Changes** (Render will automatically trigger a new deployment).
   - **Option B — Add One by One**:
     1. Click **Add Environment Variable**.
     2. Type or paste the variable **Key** (e.g., `DATABASE_URL`) and its corresponding **Value**.
     3. Click **Add Environment Variable** again for each additional key-value pair.
     4. Click **Save Changes**.

   #### Required & Recommended Environment Variables:

| Category | Key | Example / Recommended Value | Purpose |
| :--- | :--- | :--- | :--- |
| **Runtime & Host** | `PYTHON_VERSION` | `3.11.9` | Enforces stable Python 3.11 runtime on Render |
| **Runtime & Host** | `HOST` | `0.0.0.0` | Binds FastAPI server to all network interfaces |
| **CORS / Security** | `ALLOW_ALL_ORIGINS` | `true` | Allows cross-origin requests from your Vercel frontend |
| **Database (Neon)** | `DATABASE_URL` | `postgresql://user:pass@ep-xyz.neon.tech/neondb?sslmode=require` | Neon Postgres connection URI for report & result storage |
| **Storage (Cloudinary)** | `CLOUDINARY_CLOUD_NAME` | `your_cloud_name` | Cloudinary account name for PCAP backups |
| **Storage (Cloudinary)** | `CLOUDINARY_API_KEY` | `your_api_key` | Cloudinary API Key |
| **Storage (Cloudinary)** | `CLOUDINARY_API_SECRET` | `your_api_secret` | Cloudinary API Secret |
| **AI Engine (Gemini)** | `GEMINI_API_KEY` | `your_gemini_api_key` | Google Gemini API key for AI traffic classification & remediation |
| **AI Engine (Gemini)** | `GEMINI_MODEL` | `gemini-3.5-flash-lite` | Default Gemini model identifier |
| **AI Engine (Gemini)** | `ENABLE_CLOUD_LLM` | `true` | Enables AI cloud LLM features in backend remediation |
| **Inference Mode** | `CLASSIFIER_BACKEND` | `llm` | Inference mode: `llm` (Gemini API) or `cnn` (local ONNX model) |
| **Analyzer Mode** | `ANALYZER_MODE` | `real` | Analyzer pipeline: `real` (live parsing) or `mock` (sample demo data) |

   #### Copy-Pasteable `.env` Block for Render:
   ```env
   PYTHON_VERSION=3.11.9
   HOST=0.0.0.0
   ALLOW_ALL_ORIGINS=true
   DATABASE_URL=postgresql://user:password@ep-xyz.eu-central-1.aws.neon.tech/neondb?sslmode=require
   CLOUDINARY_CLOUD_NAME=your_cloud_name
   CLOUDINARY_API_KEY=your_api_key
   CLOUDINARY_API_SECRET=your_api_secret
   GEMINI_API_KEY=your_gemini_api_key
   GEMINI_MODEL=gemini-3.5-flash-lite
   ENABLE_CLOUD_LLM=true
   CLASSIFIER_BACKEND=llm
   ANALYZER_MODE=real
   ```

   > [!NOTE]
   > Whenever you save or modify environment variables in Render, Render triggers an automatic zero-downtime re-deploy. You can watch progress live under the **Events** and **Logs** tabs in your Render service dashboard.

6. Click **Deploy Web Service** (or let the auto-deploy triggered by saving environment variables complete).
7. Note down your Render backend URL once deployment finishes (e.g., `https://cryptolens-backend.onrender.com`).

---

## 6. Setup 24/7 Keep-Alive with cron-job.org

Render's free tier shuts down services after 15 minutes of inactivity. Use `cron-job.org` to send periodic requests:

1. Register at [cron-job.org](https://cron-job.org).
2. In the dashboard, click **Create Cronjob**.
3. Fill in:
   - **Title**: `CryptoLens Backend Keepalive`
   - **URL**: `https://cryptolens-backend.onrender.com/health`
   - **Schedule**: User-defined → **Every 10 minutes**
   - **Request Method**: `GET`
   - **Notification**: Disable failure alerts or set to notify only on consecutive failures
4. Click **Create**. The backend will now stay permanently awake and responsive.

---

## 7. Deploy Frontend to Vercel

1. Log into [Vercel](https://vercel.com).
2. Click **Add New...** → **Project**.
3. Select your `CryptoLens` GitHub repository.
4. Under **Project Settings**:
   - **Framework Preset**: `Vite`
   - **Root Directory**: `./`
   - **Build Command**: `npm run build`
   - **Output Directory**: `dist`
   - **Install Command**: `npm install`
5. Ensure `vercel.json` in your repository points to your live Render backend URL:
   ```json
   {
     "rewrites": [
       {
         "source": "/api/:path*",
         "destination": "https://cryptolens-backend.onrender.com/api/:path*"
       },
       {
         "source": "/(.*)",
         "destination": "/index.html"
       }
     ]
   }
   ```
6. Click **Deploy**.

---

## 8. Verification & Validation Checklist

| Item | Validation Step | Expected Result |
| :--- | :--- | :--- |
| **Backend Health** | Open `https://<render-url>/health` | Returns `{"status": "healthy", ...}` with HTTP 200 |
| **Keepalive** | Check history log in `cron-job.org` | Shows periodic HTTP 200 status every 10 min |
| **Frontend Access** | Open `https://<vercel-url>` | SPA loads instantly with all styles and charts |
| **Subpage Refresh** | Navigate to `/reports` and press `Ctrl+R` | Page reloads without Vercel 404 errors |
| **State Preservation** | Run a capture analysis, then refresh mid-flight | Session restores from `localStorage` without data loss |
| **PDF Storage in Neon** | Generate and download a PDF report | `SELECT count(*) FROM generated_reports;` in Neon increases |
| **Cloudinary Ingestion**| Upload a PCAP file | Capture is backed up to Cloudinary cloud repository |
