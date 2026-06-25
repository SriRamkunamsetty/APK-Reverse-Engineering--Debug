"""
RAKSHAK — Distributed Task Queue (Celery + Redis)
Enables parallel APK analysis across multiple workers.
DRDO deployment: scale to 20+ concurrent analyses.
Run workers: celery -A core.task_queue worker --loglevel=info --concurrency=4
"""

import os, json
from pathlib import Path
from datetime import datetime

# ── Try Celery; fallback to synchronous if Redis unavailable ─────────────────
try:
    from celery import Celery
    CELERY_AVAILABLE = True
except ImportError:
    CELERY_AVAILABLE = False

REDIS_URL   = os.getenv("REDIS_URL",   "redis://localhost:6379/0")
BROKER_URL  = os.getenv("BROKER_URL",  REDIS_URL)
BACKEND_URL = os.getenv("BACKEND_URL", REDIS_URL)


def make_celery_app():
    if not CELERY_AVAILABLE:
        return None
    app = Celery(
        "rakshak",
        broker  = BROKER_URL,
        backend = BACKEND_URL,
    )
    app.conf.update(
        task_serializer        = "json",
        result_serializer      = "json",
        accept_content         = ["json"],
        timezone               = "UTC",
        enable_utc             = True,
        task_track_started     = True,
        task_acks_late         = True,          # Redeliver on worker crash
        worker_prefetch_multiplier = 1,         # Fair distribution
        task_routes            = {
            "core.task_queue.analyze_apk_task"   : {"queue": "analysis"},
            "core.task_queue.ml_analysis_task"   : {"queue": "ml"},
            "core.task_queue.network_enrich_task": {"queue": "enrich"},
            "core.task_queue.ct_scan_task"       : {"queue": "intel"},
        },
        beat_schedule          = {
            "ct-monitor-every-5min": {
                "task"    : "core.task_queue.ct_scan_task",
                "schedule": 300.0,              # Every 5 minutes
                "args"    : (),
            },
        },
    )
    return app


celery_app = make_celery_app()

# ── Task definitions ──────────────────────────────────────────────────────────
if celery_app:

    @celery_app.task(bind=True, name="core.task_queue.analyze_apk_task",
                     max_retries=2, soft_time_limit=280, time_limit=300)
    def analyze_apk_task(self, apk_path: str, case_id: str,
                         analyst: str = "RAKSHAK-AUTO") -> dict:
        """Full pipeline analysis task — runs on analysis queue."""
        try:
            from core.pipeline import RakshakPipeline
            pipeline = RakshakPipeline()
            result   = pipeline.analyze(apk_path, analyst_name=analyst,
                                        case_id=case_id)
            # Persist result
            from database.db import save_case
            save_case(result)
            return {"status": "COMPLETE", "case_id": case_id,
                    "risk_score": result.get("summary", {}).get("risk_score")}
        except Exception as exc:
            self.retry(exc=exc, countdown=10)

    @celery_app.task(name="core.task_queue.ml_analysis_task", soft_time_limit=60)
    def ml_analysis_task(apk_path: str, case_id: str) -> dict:
        """ML ensemble analysis — runs on ml queue."""
        from core.ml_engine import MLEnsemble
        ml = MLEnsemble()
        return ml.analyse(apk_path, case_id=case_id)

    @celery_app.task(name="core.task_queue.network_enrich_task", soft_time_limit=30)
    def network_enrich_task(urls: list, ips: list, case_id: str) -> dict:
        """Network IOC enrichment — runs on enrich queue."""
        from core.network_analyzer import NetworkAnalyzer
        analyzer = NetworkAnalyzer(timeout=8)
        return analyzer.analyze(urls, ips)

    @celery_app.task(name="core.task_queue.ct_scan_task")
    def ct_scan_task() -> dict:
        """Scheduled CT log scan — runs on intel queue every 5 min."""
        from core.ct_monitor import ct_monitor
        return ct_monitor.scan_all_brands()

    @celery_app.task(name="core.task_queue.misp_push_task", soft_time_limit=30)
    def misp_push_task(case_id: str) -> dict:
        """Push completed analysis to MISP — runs on enrich queue."""
        from database.db import get_case
        from core.misp_client import misp_client
        result = get_case(case_id)
        if result:
            return misp_client.push_analysis(result, case_id=case_id)
        return {"error": "Case not found"}

    @celery_app.task(name="core.task_queue.frida_task", soft_time_limit=120)
    def frida_task(apk_path: str, case_id: str) -> dict:
        """Dynamic Frida sandbox analysis — runs on analysis queue."""
        from core.frida_sandbox import FridaSandboxOrchestrator
        return FridaSandboxOrchestrator().run_analysis(apk_path, case_id)


# ── Synchronous fallback (no Redis) ──────────────────────────────────────────
class SyncTaskRunner:
    """Drop-in replacement when Celery/Redis is not available."""

    @staticmethod
    def run(task_fn, *args, **kwargs):
        """Run task synchronously and return result."""
        return task_fn(*args, **kwargs)

    @staticmethod
    def submit_analysis(apk_path: str, case_id: str,
                        analyst: str = "RAKSHAK-AUTO") -> str:
        """Submit analysis — returns task ID or case_id."""
        if celery_app:
            task = analyze_apk_task.apply_async(
                args   = [apk_path, case_id, analyst],
                task_id= case_id,
            )
            return task.id
        else:
            # Synchronous fallback
            from core.pipeline import RakshakPipeline
            result = RakshakPipeline().analyze(apk_path, analyst, case_id)
            from database.db import save_case
            save_case(result)
            return case_id


task_runner = SyncTaskRunner()
