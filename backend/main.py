import os
from dotenv import load_dotenv
load_dotenv()
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from backend.routes import analyze, results, report, capture, live, remediation, xai

app = FastAPI(
    title="IPsec Protocol Analysis API",
    version="1.0.0",
    docs_url="/docs"
)

# CORS configuration (P2-1): restrictive by default, never wildcard in prod
frontend_origin = os.getenv("FRONTEND_ORIGIN", "http://localhost:5173")
allow_all = os.getenv("ALLOW_ALL_ORIGINS", "false").lower() in ("true", "1")
origins = ["*"] if allow_all else [
    frontend_origin,
    "http://127.0.0.1:5173",
    "http://localhost:5173",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.exception_handler(Exception)
async def custom_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"error_code": "INTERNAL_SERVER_ERROR", "message": str(exc)}
    )

app.include_router(analyze.router, prefix="/api/v1", tags=["Analysis"])
app.include_router(results.router, prefix="/api/v1", tags=["Results"])
app.include_router(report.router, prefix="/api/v1", tags=["Report"])
app.include_router(capture.router, prefix="/api/v1", tags=["Capture"])
app.include_router(live.router, tags=["Live Streaming"])
app.include_router(remediation.router, tags=["Remediation"])
app.include_router(xai.router, tags=["XAI"])


@app.on_event("startup")
def log_startup_configuration():
    cloud_ai = os.getenv("ENABLE_CLOUD_LLM", "false").lower() in ("true", "1", "yes")
    provider = os.getenv("LLM_PROVIDER", "gemini" if cloud_ai else "none").strip().lower()
    fallback = os.getenv("LLM_FALLBACK_PROVIDER", "none").strip().lower()
    status_str = f"ON (Provider: {provider}, Fallback: {fallback})" if (cloud_ai and provider != "none") else "OFF (Air-gapped / Deterministic Templates only)"
    print(f"[*] CryptoLens Core initialized. Cloud AI Explainer: {status_str}")

@app.api_route("/", methods=["GET", "HEAD"])
def root():
    return {
        "status": "online",
        "service": "CryptoLens Core Analysis Engine",
        "docs": "/docs",
        "health": "/health"
    }

@app.api_route("/health", methods=["GET", "HEAD"])
def health_check():
    return {
        "status": "healthy",
        "service": "CryptoLens Core Analysis Engine",
        "version": "1.0.0"
    }

if __name__ == "__main__":
    import uvicorn
    host = os.getenv("HOST", "127.0.0.1")  # Default to 127.0.0.1 (P2-1)
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host=host, port=port)