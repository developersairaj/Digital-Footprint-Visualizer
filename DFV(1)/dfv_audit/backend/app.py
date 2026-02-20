from __future__ import annotations

from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from dfv_audit.backend.scanner import scan_text
from dfv_audit.backend.risk import score_findings


class ScanTextRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=2_000_000)
    source_name: str | None = Field(default=None, max_length=200)


app = FastAPI(
    title="DFV Audit (Local) API",
    version="1.0.0",
    description="Local, consent-based exposure scanner for digital footprint / data leak indicators.",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


@app.get("/api/health")
async def health():
    return {"ok": True, "service": "dfv-audit-local", "version": "1.0.0"}


@app.post("/api/scan/text")
async def scan_text_endpoint(req: ScanTextRequest):
    result = scan_text(req.text)
    risk = score_findings(result["findings"])
    return {
        "source": {"type": "text", "name": req.source_name},
        **result,
        "risk": risk,
    }


@app.post("/api/scan/file")
async def scan_file_endpoint(file: UploadFile = File(...)):
    # Local-only: we do not store uploads on disk.
    if not file.filename:
        raise HTTPException(status_code=400, detail="Missing filename.")

    raw = await file.read()
    if len(raw) > 5 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="File too large (limit 5MB).")

    # Best-effort decode
    text = raw.decode("utf-8", errors="ignore")
    if not text.strip():
        raise HTTPException(status_code=400, detail="Could not extract text from file.")

    result = scan_text(text)
    risk = score_findings(result["findings"])
    return {
        "source": {"type": "file", "name": file.filename, "size_bytes": len(raw)},
        **result,
        "risk": risk,
    }


# Serve the frontend (optional convenience)
app.mount(
    "/",
    StaticFiles(directory="dfv_audit/frontend", html=True),
    name="frontend",
)


@app.get("/")
async def index():
    return FileResponse("dfv_audit/frontend/index.html")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("dfv_audit.backend.app:app", host="127.0.0.1", port=8002, reload=False)

