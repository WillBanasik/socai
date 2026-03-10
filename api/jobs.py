"""Background job manager for socai investigations."""
from __future__ import annotations

import fcntl
import json
import re
import threading
import traceback
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from config.settings import BASE_DIR, CASES_DIR, REGISTRY_FILE

LOCK_FILE = BASE_DIR / "registry" / ".case_id.lock"


@dataclass
class Job:
    case_id: str
    status: str = "queued"  # queued | running | complete | failed
    error: str | None = None
    submitted: str = ""
    completed: str | None = None


class JobManager:
    """Manages background investigation jobs via a thread pool."""

    def __init__(self, max_workers: int = 2):
        self._pool = ThreadPoolExecutor(max_workers=max_workers)
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Case ID generation (file-locked, mirrors socai.py logic)
    # ------------------------------------------------------------------

    @staticmethod
    def next_case_id() -> str:
        from tools.common import load_json

        LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
        lock_fd = open(LOCK_FILE, "w")
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            max_num = 0
            if REGISTRY_FILE.exists():
                try:
                    registry = load_json(REGISTRY_FILE)
                    for cid in registry.get("cases", {}):
                        m = re.search(r"(\d+)$", cid)
                        if m:
                            max_num = max(max_num, int(m.group(1)))
                except Exception:
                    pass
            return f"IV_CASE_{max_num + 1:03d}"
        finally:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            lock_fd.close()

    # ------------------------------------------------------------------
    # Job status persistence
    # ------------------------------------------------------------------

    @staticmethod
    def _status_path(case_id: str) -> Path:
        return CASES_DIR / case_id / "job_status.json"

    def _write_status(self, job: Job) -> None:
        path = self._status_path(job.case_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(
                {
                    "case_id": job.case_id,
                    "status": job.status,
                    "error": job.error,
                    "submitted": job.submitted,
                    "completed": job.completed,
                },
                f,
                indent=2,
            )

    # ------------------------------------------------------------------
    # Submit / query
    # ------------------------------------------------------------------

    def submit(self, case_id: str, kwargs: dict) -> Job:
        now = datetime.now(timezone.utc).isoformat()
        job = Job(case_id=case_id, submitted=now)
        with self._lock:
            self._jobs[case_id] = job
        self._write_status(job)
        self._pool.submit(self._run_job, case_id, kwargs)
        return job

    def get(self, case_id: str) -> Job | None:
        # Check in-memory first, then fall back to disk
        with self._lock:
            if case_id in self._jobs:
                return self._jobs[case_id]
        path = self._status_path(case_id)
        if path.exists():
            with open(path) as f:
                data = json.load(f)
            job = Job(
                case_id=data["case_id"],
                status=data.get("status", "complete"),
                error=data.get("error"),
                submitted=data.get("submitted", ""),
                completed=data.get("completed"),
            )
            return job
        return None

    def list_active(self) -> list[Job]:
        with self._lock:
            return [j for j in self._jobs.values() if j.status in ("queued", "running")]

    # ------------------------------------------------------------------
    # Worker
    # ------------------------------------------------------------------

    def _run_job(self, case_id: str, kwargs: dict) -> None:
        with self._lock:
            job = self._jobs[case_id]
            job.status = "running"
        self._write_status(job)

        try:
            from agents.chief import ChiefAgent

            agent = ChiefAgent(case_id)
            agent.run(**kwargs)

            with self._lock:
                job.status = "complete"
                job.completed = datetime.now(timezone.utc).isoformat()
        except Exception as exc:
            with self._lock:
                job.status = "failed"
                job.error = str(exc)
                job.completed = datetime.now(timezone.utc).isoformat()
            from tools.common import log_error
            log_error(case_id, "api.jobs.run_job", str(exc),
                      severity="error", traceback=traceback.format_exc())
        finally:
            self._write_status(job)

    def shutdown(self) -> None:
        self._pool.shutdown(wait=False)
