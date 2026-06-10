"""
RAKSHAK — FastAPI REST Backend
DRDO APK Threat Intelligence Platform — API Server
"""

import os, json, uuid, shutil
from pathlib import Path
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, File, UploadFile, HTTPException, BackgroundTasks, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles   import StaticFiles
from fastapi.responses     import HTMLResponse, FileResponse, JSONResponse
from pydantic              import BaseModel

from config         import UPLOAD_DIR, REPORT_DIR, STATIC_DIR, MAX_APK_SIZE_MB
from core.pipeline  import RakshakPipeline

# ─── FastAPI App ────────────────────────────────────────────────────────────────
app = FastAPI(
    title       = "RAKSHAK APK Threat Intelligence Platform",
    description = "Defence-grade Android malware analysis for DRDO Cybersecurity Division",
    version     = "3.0.0",
    docs_url    = "/api/docs",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory job store (production: use Redis)
JOBS: dict[str, dict] = {}
pipeline = RakshakPipeline()


# ─── MODELS ─────────────────────────────────────────────────────────────────────
class QuestionRequest(BaseModel):
    case_id : str
    question: str


class QuestionResponse(BaseModel):
    case_id : str
    question: str
    answer  : str


# ─── ROUTES ─────────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def root():
    """Serve the RAKSHAK dashboard"""
    dashboard = STATIC_DIR / "dashboard.html"
    if dashboard.exists():
        return HTMLResponse(content=dashboard.read_text())
    return HTMLResponse(content="<h1>RAKSHAK v3.0 — Dashboard not built yet</h1>")


@app.get("/api/status")
async def status():
    return {
        "platform"       : "RAKSHAK v3.0",
        "status"         : "OPERATIONAL",
        "organisation"   : "DRDO Cybersecurity Division",
        "active_jobs"    : len([j for j in JOBS.values() if j.get("status") == "RUNNING"]),
        "total_analyses" : len(JOBS),
        "timestamp"      : datetime.utcnow().isoformat() + "Z",
    }


@app.post("/api/analyze")
async def analyze_apk(
    background_tasks: BackgroundTasks,
    file         : UploadFile = File(...),
    analyst_name : str = Form(default="RAKSHAK-AUTO"),
):
    """Upload and analyze an APK file"""

    # Validate file
    if not file.filename.lower().endswith(".apk"):
        raise HTTPException(status_code=400, detail="Only .apk files are accepted")

    content = await file.read()

    if len(content) > MAX_APK_SIZE_MB * 1024 * 1024:
        raise HTTPException(status_code=413,
                            detail=f"APK exceeds {MAX_APK_SIZE_MB}MB limit")

    # Check magic bytes
    if content[:4] != b'PK\x03\x04':
        raise HTTPException(status_code=400,
                            detail="Invalid APK — not a valid ZIP/APK file")

    # Generate case ID
    case_id  = f"RKSAK-{datetime.utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:8].upper()}"
    apk_path = UPLOAD_DIR / f"{case_id}.apk"

    with open(apk_path, "wb") as f:
        f.write(content)

    # Initialize job
    JOBS[case_id] = {
        "case_id"    : case_id,
        "apk_name"   : file.filename,
        "status"     : "QUEUED",
        "submitted"  : datetime.utcnow().isoformat() + "Z",
        "analyst"    : analyst_name,
        "result"     : None,
    }

    # Run analysis in background
    background_tasks.add_task(
        _run_analysis, case_id, str(apk_path), analyst_name
    )

    return {
        "case_id"   : case_id,
        "status"    : "QUEUED",
        "apk_name"  : file.filename,
        "message"   : "Analysis started — poll /api/result/{case_id} for results",
        "poll_url"  : f"/api/result/{case_id}",
    }


def _run_analysis(case_id: str, apk_path: str, analyst_name: str):
    """Background analysis task"""
    JOBS[case_id]["status"] = "RUNNING"
    try:
        result = pipeline.analyze(
            apk_path     = apk_path,
            analyst_name = analyst_name,
            case_id      = case_id,
        )
        JOBS[case_id]["status"] = result.get("status", "COMPLETE")
        JOBS[case_id]["result"] = result

        # Persist result to disk
        report_path = REPORT_DIR / f"{case_id}.json"
        with open(report_path, "w") as f:
            json.dump(result, f, indent=2, default=str)

    except Exception as e:
        JOBS[case_id]["status"] = "ERROR"
        JOBS[case_id]["error"]  = str(e)


@app.get("/api/result/{case_id}")
async def get_result(case_id: str):
    """Poll analysis result"""
    if case_id not in JOBS:
        # Try loading from disk
        report_path = REPORT_DIR / f"{case_id}.json"
        if report_path.exists():
            return JSONResponse(content=json.loads(report_path.read_text()))
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found")

    job = JOBS[case_id]
    if job["status"] in ("QUEUED", "RUNNING"):
        return {
            "case_id": case_id,
            "status" : job["status"],
            "message": "Analysis in progress — please wait",
            "progress": job.get("result", {}).get("progress", []),
        }
    return job.get("result") or {"case_id": case_id, "status": job["status"]}


@app.get("/api/jobs")
async def list_jobs():
    """List all analysis jobs"""
    return {
        "total": len(JOBS),
        "jobs" : [
            {
                "case_id"  : case_id,
                "apk_name" : job["apk_name"],
                "status"   : job["status"],
                "submitted": job["submitted"],
                "risk_score": job.get("result", {}).get("risk_score", {}).get("final_score"),
                "severity"  : job.get("result", {}).get("risk_score", {}).get("severity"),
            }
            for case_id, job in sorted(JOBS.items(), reverse=True)
        ]
    }


@app.post("/api/question", response_model=QuestionResponse)
async def analyst_question(req: QuestionRequest):
    """Analyst Q&A — ask Claude about a completed analysis"""
    job = JOBS.get(req.case_id)
    if not job:
        report_path = REPORT_DIR / f"{req.case_id}.json"
        if report_path.exists():
            analysis = json.loads(report_path.read_text())
        else:
            raise HTTPException(status_code=404, detail="Case not found")
    else:
        analysis = job.get("result")
        if not analysis:
            raise HTTPException(status_code=400, detail="Analysis not yet complete")

    answer = pipeline.answer_question(req.question, analysis)
    return QuestionResponse(
        case_id  = req.case_id,
        question = req.question,
        answer   = answer,
    )


@app.get("/api/report/{case_id}")
async def download_report(case_id: str):
    """Download full JSON report"""
    report_path = REPORT_DIR / f"{case_id}.json"
    if not report_path.exists():
        # Try from in-memory
        job = JOBS.get(case_id)
        if job and job.get("result"):
            with open(report_path, "w") as f:
                json.dump(job["result"], f, indent=2, default=str)
        else:
            raise HTTPException(status_code=404, detail="Report not found")
    return FileResponse(
        path        = str(report_path),
        filename    = f"RAKSHAK-{case_id}-report.json",
        media_type  = "application/json",
    )


@app.delete("/api/case/{case_id}")
async def delete_case(case_id: str):
    """Remove a case and associated files"""
    if case_id in JOBS:
        del JOBS[case_id]
    apk_path    = UPLOAD_DIR / f"{case_id}.apk"
    report_path = REPORT_DIR / f"{case_id}.json"
    for p in [apk_path, report_path]:
        if p.exists():
            p.unlink()
    return {"message": f"Case {case_id} deleted"}


# ─── ENTRY POINT ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    print("=" * 60)
    print("  RAKSHAK APK Threat Intelligence Platform v3.0")
    print("  DRDO Cybersecurity Division")
    print("=" * 60)
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)


# ─── ADDITIONAL ENDPOINTS ─────────────────────────────────────────────────────

@app.get("/api/report/{case_id}/pdf")
async def download_pdf_report(case_id: str):
    """Generate and download PDF forensic report"""
    from core.report_engine import generate_pdf_report

    job = JOBS.get(case_id)
    if not job:
        from database.db import get_case
        result = get_case(case_id)
    else:
        result = job.get("result")

    if not result:
        raise HTTPException(status_code=404, detail="Case not found or analysis not complete")

    pdf_path = str(REPORT_DIR / f"{case_id}-technical.pdf")
    if not Path(pdf_path).exists():
        try:
            pdf_path = generate_pdf_report(result, str(REPORT_DIR))
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"PDF generation failed: {e}")

    return FileResponse(
        path       = pdf_path,
        filename   = f"RAKSHAK-{case_id}-forensic-report.pdf",
        media_type = "application/pdf",
    )


@app.get("/api/report/{case_id}/stix")
async def export_stix(case_id: str):
    """Export analysis as STIX 2.1 threat intelligence bundle"""
    from core.stix_exporter import export_stix as _export

    job = JOBS.get(case_id)
    result = job.get("result") if job else None
    if not result:
        from database.db import get_case
        result = get_case(case_id)
    if not result:
        raise HTTPException(status_code=404, detail="Case not found")

    bundle = _export(result)
    stix_path = REPORT_DIR / f"{case_id}-stix.json"
    stix_path.write_text(json.dumps(bundle, indent=2))

    return FileResponse(
        path       = str(stix_path),
        filename   = f"RAKSHAK-{case_id}-stix21.json",
        media_type = "application/json",
    )


@app.post("/api/network/{case_id}")
async def run_network_analysis(case_id: str):
    """Run network IOC enrichment on a completed analysis"""
    from core.network_analyzer import NetworkAnalyzer

    job = JOBS.get(case_id)
    result = job.get("result") if job else None
    if not result:
        from database.db import get_case
        result = get_case(case_id)
    if not result:
        raise HTTPException(status_code=404, detail="Case not found")

    strings = result.get("strings", {})
    analyzer = NetworkAnalyzer(timeout=6)
    net_result = analyzer.analyze(
        urls = strings.get("urls", []),
        ips  = strings.get("ips",  []),
    )
    if job:
        if job.get("result"):
            job["result"]["network_analysis"] = net_result
    return net_result


@app.get("/api/stats")
async def platform_stats():
    """Platform-wide statistics from database"""
    from database.db import get_stats
    db_stats = get_stats()
    return {
        **db_stats,
        "active_jobs"    : len([j for j in JOBS.values() if j.get("status") == "RUNNING"]),
        "in_memory_jobs" : len(JOBS),
        "platform"       : "RAKSHAK v3.0.0",
        "timestamp"      : datetime.utcnow().isoformat() + "Z",
    }


@app.get("/api/cases")
async def list_all_cases(limit: int = 50):
    """List cases from persistent database"""
    from database.db import list_cases
    return {"cases": list_cases(limit=limit)}


@app.get("/api/ioc/search")
async def search_ioc(q: str):
    """Search IOC value across all cases"""
    from database.db import search_ioc as _search
    return {"results": _search(q)}


# ─── WEBSOCKET REAL-TIME STREAMING ───────────────────────────────────────────
from fastapi import WebSocket, WebSocketDisconnect
from core.ws_server import ws_manager
from core.event_bus import event_bus


@app.websocket("/ws/analysis/{case_id}")
async def ws_analysis(websocket: WebSocket, case_id: str):
    """Per-case WebSocket — streams all events for a specific analysis."""
    await ws_manager.connect(websocket, case_id=case_id)


@app.websocket("/ws/global")
async def ws_global(websocket: WebSocket):
    """Global WebSocket — receives ALL analysis events across all cases."""
    await ws_manager.connect(websocket, case_id=None)


@app.get("/api/events/{case_id}")
async def get_event_history(case_id: str):
    """Replay all recorded events for a case (for dashboard catch-up)."""
    return {"case_id": case_id, "events": event_bus.get_history(case_id)}


@app.post("/api/analyze/advanced")
async def analyze_advanced(
    background_tasks: BackgroundTasks,
    file          : UploadFile = File(...),
    analyst_name  : str = Form(default="RAKSHAK-AUTO"),
    enable_dynamic: bool = Form(default=True),
    enable_network: bool = Form(default=True),
    enable_misp   : bool = Form(default=False),
):
    """Advanced analysis endpoint using all 11 engines with real-time streaming."""
    if not file.filename.lower().endswith(".apk"):
        raise HTTPException(400, "Only .apk files accepted")
    content = await file.read()
    if len(content) > MAX_APK_SIZE_MB * 1024 * 1024:
        raise HTTPException(413, f"APK exceeds {MAX_APK_SIZE_MB}MB")
    if content[:4] != b'PK\x03\x04':
        raise HTTPException(400, "Invalid APK file")

    import uuid
    case_id  = f"RKSAK-{datetime.utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:8].upper()}"
    apk_path = UPLOAD_DIR / f"{case_id}.apk"
    with open(apk_path, "wb") as f:
        f.write(content)

    JOBS[case_id] = {
        "case_id"  : case_id,
        "apk_name" : file.filename,
        "status"   : "QUEUED",
        "submitted": datetime.utcnow().isoformat() + "Z",
        "analyst"  : analyst_name,
        "result"   : None,
    }

    def _run():
        JOBS[case_id]["status"] = "RUNNING"
        try:
            from core.advanced_pipeline import AdvancedPipeline
            from database.db import save_case
            result = AdvancedPipeline().analyze(
                str(apk_path), analyst_name, case_id,
                enable_dynamic=enable_dynamic,
                enable_network=enable_network,
                enable_misp   =enable_misp,
            )
            JOBS[case_id]["status"] = result.get("status","COMPLETE")
            JOBS[case_id]["result"] = result
            save_case(result)
            report_path = REPORT_DIR / f"{case_id}.json"
            report_path.write_text(json.dumps(result, indent=2, default=str))
        except Exception as e:
            JOBS[case_id]["status"] = "ERROR"
            JOBS[case_id]["error"]  = str(e)

    background_tasks.add_task(_run)
    return {
        "case_id"  : case_id,
        "status"   : "QUEUED",
        "apk_name" : file.filename,
        "ws_url"   : f"/ws/analysis/{case_id}",
        "poll_url" : f"/api/result/{case_id}",
        "message"  : "Connect WebSocket to receive real-time events",
    }
