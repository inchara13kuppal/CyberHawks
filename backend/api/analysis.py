"""
Garudatva v3 — Analysis API
POST /analyze          — upload APK, validate, start pipeline
GET  /status/{id}      — Server-Sent Events stream for live pipeline updates
GET  /result/{id}      — complete JSON result
GET  /custody/{id}     — custody chain manifest
GET  /custody/{id}/verify — verify chain integrity
"""

from __future__ import annotations

import asyncio
import json
import uuid
from pathlib import Path
from typing import AsyncGenerator

import aiofiles
from fastapi import APIRouter, File, Form, HTTPException, UploadFile
from fastapi.responses import JSONResponse, StreamingResponse

from config import settings
from core.pipeline import start_analysis, get_job_status, get_job_results
from models.analysis import AnalysisRequest, CaseMetadata, OfficerInfo, DeviceInfo
from utils.hasher import sha256_file
from utils.logger import get_logger

logger = get_logger(__name__)
router = APIRouter()

# In-memory case store (keyed by case_id)
_cases: dict = {}


@router.post("/cases")
async def create_case(case: CaseMetadata):
    """
    Register case metadata from the Case Setup Wizard.
    Returns case_id. Must be called before /analyze.
    """
    _cases[case.case_id] = case
    logger.info(f"Case registered: {case.case_id} FIR={case.fir_number}")
    return {"case_id": case.case_id, "status": "registered"}


@router.post("/analyze")
async def analyze_apk(
    case_id: str = Form(...),
    file: UploadFile = File(...),
):
    """
    Upload APK for analysis.
    Validates file, computes SHA256, starts pipeline.
    Returns analysis_id for status polling.
    """
    # Validate case exists
    case = _cases.get(case_id)
    if not case:
        raise HTTPException(
            status_code=404,
            detail=f"Case {case_id} not found. Complete Case Setup Wizard first.",
        )

    # Validate file extension
    filename = file.filename or "unknown.apk"
    if not filename.lower().endswith(".apk"):
        raise HTTPException(status_code=400, detail="Only .apk files accepted")

    # Save uploaded file
    analysis_id = str(uuid.uuid4())
    upload_path = settings.UPLOAD_DIR / analysis_id
    upload_path.mkdir(parents=True, exist_ok=True)
    apk_path = upload_path / filename

    async with aiofiles.open(apk_path, "wb") as f:
        content = await file.read()
        await f.write(content)

    # Compute SHA256
    apk_sha256 = sha256_file(apk_path)
    logger.info(f"APK uploaded: {filename} sha256={apk_sha256[:16]}…")

    request = AnalysisRequest(
        case_id=case_id,
        apk_filename=filename,
        apk_sha256=apk_sha256,
    )

    # Start pipeline (non-blocking)
    await start_analysis(request, case, apk_path)

    return {
        "analysis_id": analysis_id,
        "case_id": case_id,
        "filename": filename,
        "sha256": apk_sha256,
        "status": "pipeline_started",
        "status_url": f"/api/v1/status/{analysis_id}",
        "result_url": f"/api/v1/result/{analysis_id}",
    }


@router.get("/status/{analysis_id}")
async def stream_status(analysis_id: str):
    """
    Server-Sent Events stream for real-time pipeline stage updates.
    Frontend connects here and receives live progress.
    """
    async def event_generator() -> AsyncGenerator[str, None]:
        last_stage = None
        timeout = 0

        while timeout < 3600:   # max 1 hour stream
            status = get_job_status(analysis_id)

            if status is None:
                yield _sse_event({"error": "analysis_id not found"})
                return

            event_data = {
                "analysis_id": analysis_id,
                "current_stage": status.current_stage,
                "risk_score": status.risk_score,
                "risk_tier": status.risk_tier,
                "stages": {
                    name: {
                        "status": sr.status,
                        "duration_seconds": sr.duration_seconds,
                        "artifacts": sr.artifacts,
                        "error": sr.error,
                    }
                    for name, sr in status.stages.items()
                },
            }

            yield _sse_event(event_data)

            if status.current_stage in ("COMPLETE", "FAILED"):
                return

            await asyncio.sleep(1.5)
            timeout += 1.5

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/result/{analysis_id}")
async def get_result(analysis_id: str):
    """Return complete analysis result JSON."""
    status = get_job_status(analysis_id)
    if not status:
        raise HTTPException(status_code=404, detail="Analysis not found")

    results = get_job_results(analysis_id)

    return {
        "analysis_id": analysis_id,
        "status": status.current_stage,
        "risk_score": status.risk_score,
        "risk_tier": status.risk_tier,
        "stages": status.stages,
        "results": {
            k: _serialize_result(v)
            for k, v in (results or {}).items()
            if k not in ("static", "dynamic")   # large objects — use dedicated endpoints
        },
    }


@router.get("/custody/{analysis_id}")
async def get_custody_chain(analysis_id: str):
    """Return the full custody chain manifest for this analysis."""
    chain_path = settings.ARTIFACT_DIR / analysis_id / "custody_chain.json"
    if not chain_path.exists():
        raise HTTPException(status_code=404, detail="Custody chain not found")
    return JSONResponse(content=json.loads(chain_path.read_text()))


@router.get("/custody/{analysis_id}/verify")
async def verify_custody_chain(analysis_id: str):
    """Verify chain integrity — recomputes all hashes."""
    chain_path = settings.ARTIFACT_DIR / analysis_id / "custody_chain.json"
    if not chain_path.exists():
        raise HTTPException(status_code=404, detail="Custody chain not found")

    from core.custody_chain import CustodyChain
    try:
        chain = CustodyChain.load(chain_path)
        return {"valid": True, "entry_count": chain.entry_count}
    except ValueError as e:
        return {"valid": False, "error": str(e)}


# ── Helpers ──────────────────────────────────────────────────────────────────

def _sse_event(data: dict) -> str:
    return f"data: {json.dumps(data)}\n\n"


def _serialize_result(obj):
    """Best-effort serialization of arbitrary result objects."""
    if obj is None:
        return None
    if isinstance(obj, (str, int, float, bool)):
        return obj
    if isinstance(obj, dict):
        return {k: _serialize_result(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_serialize_result(i) for i in obj]
    if hasattr(obj, "model_dump"):
        return obj.model_dump()
    if hasattr(obj, "__dict__"):
        return {k: _serialize_result(v) for k, v in obj.__dict__.items()
                if not k.startswith("_")}
    return str(obj)
