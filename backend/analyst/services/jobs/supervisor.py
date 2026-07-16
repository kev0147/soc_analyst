import json
import os
import socket
import subprocess
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path

from django.conf import settings


def _runtime_dir() -> Path:
    path = Path(settings.BASE_DIR) / ".runtime"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _status_path() -> Path:
    return _runtime_dir() / "background_worker.json"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _write_status(payload: dict):
    path = _status_path()
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    temporary.replace(path)


class WorkerHeartbeat:
    def __init__(self, error_callback=None):
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._publish_lock = threading.Lock()
        self._started_at = _utc_now()
        self._state = "idle"
        self._current_job_id = None
        self._error_callback = error_callback
        self._last_error = ""
        self._thread = threading.Thread(target=self._run, name="worker-heartbeat", daemon=True)

    def __enter__(self):
        self._publish("running")
        self._thread.start()
        return self

    def set_current_job(self, job_id: str | None):
        with self._lock:
            self._current_job_id = str(job_id) if job_id else None
            self._state = "busy" if job_id else "idle"
        self._publish("running")

    def _payload(self, process_status: str) -> dict:
        with self._lock:
            state = self._state
            current_job_id = self._current_job_id
        return {
            "process_status": process_status,
            "state": state,
            "pid": os.getpid(),
            "hostname": socket.gethostname(),
            "started_at": self._started_at,
            "last_heartbeat_at": _utc_now(),
            "current_job_id": current_job_id,
        }

    def _publish(self, process_status: str):
        try:
            with self._publish_lock:
                _write_status(self._payload(process_status))
        except OSError as exc:
            message = f"Heartbeat worker impossible : {exc}"
            if self._error_callback and message != self._last_error:
                self._error_callback(message)
            self._last_error = message

    def _run(self):
        interval = max(float(settings.WORKER_HEARTBEAT_SECONDS), 1.0)
        while not self._stop.wait(interval):
            self._publish("running")

    def __exit__(self, exc_type, exc, traceback):
        self._stop.set()
        self._thread.join(timeout=2)
        self._publish("stopped")


def _worker_lock_is_held() -> bool:
    path = Path(settings.BASE_DIR) / ".background_jobs.lock"
    if not path.exists():
        return False
    handle = path.open("a+b")
    if path.stat().st_size == 0:
        handle.write(b"0")
        handle.flush()
    try:
        if os.name == "nt":
            import msvcrt

            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    except OSError:
        return True
    finally:
        handle.close()
    return False


def _lock_based_status(detail: str) -> dict:
    if not _worker_lock_is_held():
        return {
            "status": "offline",
            "state": "offline",
            "pid": None,
            "hostname": "",
            "started_at": None,
            "last_heartbeat_at": None,
            "heartbeat_age_seconds": None,
            "current_job_id": None,
            "detail": detail,
        }
    current_job_id = None
    state = "idle"
    try:
        from analyst.models import BackgroundJob
        from analyst.models.choices import BackgroundJobStatus

        current_job_id = (
            BackgroundJob.objects.filter(status=BackgroundJobStatus.RUNNING)
            .values_list("id", flat=True)
            .first()
        )
        state = "busy" if current_job_id else "idle"
    except Exception:
        state = "unknown"
    return {
        "status": "running",
        "state": state,
        "pid": None,
        "hostname": socket.gethostname(),
        "started_at": None,
        "last_heartbeat_at": None,
        "heartbeat_age_seconds": None,
        "current_job_id": str(current_job_id) if current_job_id else None,
        "detail": f"{detail} Worker détecté grâce au verrou local.",
    }


def worker_status() -> dict:
    path = _status_path()
    if not path.exists():
        return _lock_based_status("Fichier heartbeat absent.")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        last_heartbeat = datetime.fromisoformat(payload["last_heartbeat_at"])
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
        return _lock_based_status("Fichier heartbeat illisible.")

    age = max((datetime.now(timezone.utc) - last_heartbeat).total_seconds(), 0)
    process_status = payload.get("process_status")
    alive = process_status == "running" and age <= float(settings.WORKER_STALE_SECONDS)
    if process_status == "running" and not alive:
        return _lock_based_status("Heartbeat expiré.")
    return {
        "status": "running" if alive else ("stopped" if process_status == "stopped" else "offline"),
        "state": payload.get("state", "unknown") if alive else "offline",
        "pid": payload.get("pid"),
        "hostname": payload.get("hostname", ""),
        "started_at": payload.get("started_at"),
        "last_heartbeat_at": payload.get("last_heartbeat_at"),
        "heartbeat_age_seconds": round(age, 1),
        "current_job_id": payload.get("current_job_id") if alive else None,
        "detail": "Heartbeat actif." if alive else "Worker arrêté proprement.",
    }


def start_background_worker() -> dict:
    current = worker_status()
    if current["status"] == "running":
        return {**current, "already_running": True}

    runtime_dir = _runtime_dir()
    log_path = runtime_dir / "background_worker.log"
    manage_py = Path(settings.BASE_DIR) / "manage.py"
    log_handle = log_path.open("ab")
    kwargs = {
        "cwd": str(settings.BASE_DIR),
        "stdout": log_handle,
        "stderr": subprocess.STDOUT,
        "stdin": subprocess.DEVNULL,
    }
    if os.name == "nt":
        kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
    else:
        kwargs["start_new_session"] = True
    try:
        process = subprocess.Popen(
            [sys.executable, str(manage_py), "run_background_jobs"],
            **kwargs,
        )
    finally:
        log_handle.close()
    return {
        "status": "starting",
        "state": "starting",
        "pid": process.pid,
        "hostname": socket.gethostname(),
        "started_at": _utc_now(),
        "last_heartbeat_at": None,
        "heartbeat_age_seconds": None,
        "current_job_id": None,
        "already_running": False,
    }


def worker_log_tail(line_limit: int = 100) -> dict:
    line_limit = min(max(int(line_limit or 100), 1), 500)
    files = []
    for filename in ("background_worker.log", "worker.out.log", "worker.err.log"):
        path = _runtime_dir() / filename
        if not path.exists():
            continue
        try:
            with path.open("rb") as handle:
                handle.seek(0, os.SEEK_END)
                size = handle.tell()
                handle.seek(max(size - 128_000, 0))
                content = handle.read().decode("utf-8", errors="replace")
        except OSError as exc:
            files.append({"name": filename, "lines": [f"Lecture impossible : {exc}"]})
            continue
        files.append({"name": filename, "lines": content.splitlines()[-line_limit:]})
    return {"line_limit": line_limit, "files": files}
