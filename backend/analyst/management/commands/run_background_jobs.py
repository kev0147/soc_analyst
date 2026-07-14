import os
import time
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from analyst.models import BackgroundJob
from analyst.models.choices import BackgroundJobStatus
from analyst.services.jobs.tasks import execute_background_job, fail_interrupted_jobs


class WorkerLock:
    def __init__(self, path: Path):
        self.path = path
        self.handle = None

    def __enter__(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.handle = self.path.open("a+b")
        if self.path.stat().st_size == 0:
            self.handle.write(b"0")
            self.handle.flush()
        try:
            if os.name == "nt":
                import msvcrt

                self.handle.seek(0)
                msvcrt.locking(self.handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(self.handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            self.handle.close()
            raise CommandError("Un worker de jobs est déjà actif.") from exc
        return self

    def __exit__(self, exc_type, exc, traceback):
        if not self.handle:
            return
        try:
            if os.name == "nt":
                import msvcrt

                self.handle.seek(0)
                msvcrt.locking(self.handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(self.handle.fileno(), fcntl.LOCK_UN)
        finally:
            self.handle.close()


class Command(BaseCommand):
    help = "Exécute les imports CSV et analyses IP placés dans la file persistante."

    def add_arguments(self, parser):
        parser.add_argument(
            "--once",
            action="store_true",
            help="Traite les jobs actuellement en file puis s'arrête.",
        )
        parser.add_argument(
            "--poll-seconds",
            type=float,
            default=settings.BACKGROUND_JOBS_POLL_SECONDS,
            help="Délai entre deux lectures de la file lorsqu'elle est vide.",
        )

    def handle(self, *args, **options):
        once = options["once"]
        poll_seconds = max(options["poll_seconds"], 0.1)
        lock_path = Path(settings.BASE_DIR) / ".background_jobs.lock"

        with WorkerLock(lock_path):
            recovered = fail_interrupted_jobs()
            if recovered:
                self.stdout.write(self.style.WARNING(f"{recovered} job(s) interrompu(s) marqué(s) en échec."))
            self.stdout.write(self.style.SUCCESS("Worker de jobs démarré."))

            try:
                while True:
                    job_id = (
                        BackgroundJob.objects.filter(status=BackgroundJobStatus.QUEUED)
                        .order_by("created_at")
                        .values_list("id", flat=True)
                        .first()
                    )
                    if job_id is None:
                        if once:
                            break
                        time.sleep(poll_seconds)
                        continue

                    self.stdout.write(f"Traitement du job {job_id}...")
                    try:
                        execute_background_job(str(job_id))
                    except Exception as exc:
                        self.stderr.write(self.style.ERROR(f"Job {job_id} échoué : {exc}"))
                    else:
                        self.stdout.write(self.style.SUCCESS(f"Job {job_id} terminé."))
            except KeyboardInterrupt:
                self.stdout.write("Arrêt demandé.")

            self.stdout.write(self.style.SUCCESS("Worker de jobs arrêté."))
