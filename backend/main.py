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

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
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