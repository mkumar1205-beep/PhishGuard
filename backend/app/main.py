from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routes import analyze, qr, report
from app.database import init_db

app = FastAPI(
    title="PhishGuard AI",
    description="AI-powered phishing detection for Indian users",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def startup():
    await init_db()

app.include_router(analyze.router, prefix="/analyze", tags=["Analysis"])
app.include_router(qr.router, prefix="/analyze/qr", tags=["QR"])
app.include_router(report.router, prefix="/report", tags=["Reports"])

@app.get("/health")
def health():
    return {"status": "ok", "service": "PhishGuard AI"}
