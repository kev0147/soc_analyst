import { DatePipe } from '@angular/common';
import { Component, NgZone, OnDestroy, OnInit, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ApiService } from '../../core/api/api.service';
import { AuthService } from '../../core/auth/auth.service';
import { BackgroundJob, WorkerLogs, WorkerStatus } from '../../core/api/api.types';

@Component({
  selector: 'app-workers-page',
  standalone: true,
  imports: [DatePipe, FormsModule],
  template: `
    <div class="page">
      <div class="page-title">
        <div>
          <h1>Workers</h1>
          <p>Démarrer le worker local et suivre les imports et analyses placés dans la file.</p>
        </div>
        <button class="btn secondary" (click)="load()">Rafraîchir</button>
      </div>

      <section class="card">
        <h2>Worker de traitements</h2>
        @if (worker(); as item) {
          <div class="grid cols-3">
            <div><span class="muted">État</span><p><span class="badge" [class.success]="item.status === 'running'" [class.danger]="item.status === 'offline'">{{ item.status }} / {{ item.state }}</span></p></div>
            <div><span class="muted">Processus</span><p>PID {{ item.pid || '-' }} · {{ item.hostname || '-' }}</p></div>
            <div><span class="muted">Heartbeat</span><p>{{ item.last_heartbeat_at ? (item.last_heartbeat_at | date:'medium') : '-' }}</p></div>
            <div><span class="muted">Job courant</span><p>{{ item.current_job_id || '-' }}</p></div>
          </div>
          @if (item.detail) { <p class="muted">{{ item.detail }}</p> }
          @if (isAdmin()) {
            <button class="btn" (click)="start()" [disabled]="item.status === 'running'">Démarrer le worker</button>
          }
          @if (item.status === 'offline') {
            <p class="muted">Si un ancien worker a été lancé avant la mise à jour, arrête-le d’abord : il peut conserver le verrou sans produire de heartbeat.</p>
          }
        } @else {
          <div class="empty">Chargement du statut...</div>
        }
        <p class="muted">Le mode SQLite accepte un seul worker pour éviter les écritures concurrentes.</p>
        @if (message()) { <p class="muted">{{ message() }}</p> }
      </section>

      @if (isAdmin()) {
        <section class="card">
          <div class="page-title">
            <div><h2>Diagnostic du worker</h2><p>Dernières lignes écrites par les différents modes de lancement.</p></div>
            <button class="btn secondary" (click)="loadLogs()">Actualiser les logs</button>
          </div>
          @if (logs(); as output) {
            @for (file of output.files; track file.name) {
              <h3>{{ file.name }}</h3>
              <pre>{{ file.lines.join('\n') || 'Fichier vide.' }}</pre>
            } @empty {
              <div class="empty">Aucun journal worker. Le worker n’a probablement jamais démarré depuis cette installation.</div>
            }
          }
        </section>
      }

      <section class="card">
        <div class="page-title">
          <h2>File et historique des jobs</h2>
          <label class="field">
            <span>Statut</span>
            <select class="select" [(ngModel)]="jobStatus" (ngModelChange)="loadJobs()">
              <option value="">Tous</option>
              <option value="queued">En attente</option>
              <option value="running">En cours</option>
              <option value="completed">Terminés</option>
              <option value="failed">Échoués</option>
              <option value="canceled">Annulés</option>
            </select>
          </label>
        </div>
        <div class="table-wrap">
          <table>
            <thead><tr><th>Type</th><th>Statut</th><th>Progression</th><th>Message</th><th>Créé</th><th>Terminé</th><th></th></tr></thead>
            <tbody>
              @for (job of jobs(); track job.id) {
                <tr>
                  <td>{{ job.kind }}</td>
                  <td><span class="badge" [class.success]="job.status === 'completed'" [class.warning]="job.status === 'queued' || job.status === 'running'" [class.danger]="job.status === 'failed'">{{ job.cancel_requested_at && job.status === 'running' ? 'arrêt demandé' : job.status }}</span></td>
                  <td>{{ job.progress_percent === null ? job.progress_current : job.progress_percent + '%' }}</td>
                  <td>{{ job.error_message || job.status_message || '-' }}</td>
                  <td>{{ job.created_at | date:'medium' }}</td>
                  <td>{{ job.completed_at ? (job.completed_at | date:'medium') : '-' }}</td>
                  <td class="toolbar">
                    @if (job.can_cancel) { <button class="btn secondary" (click)="cancel(job)">Arrêter</button> }
                    @if (job.can_retry) { <button class="btn secondary" (click)="retry(job)">Relancer</button> }
                  </td>
                </tr>
              } @empty {
                <tr><td colspan="7"><div class="empty">Aucun job.</div></td></tr>
              }
            </tbody>
          </table>
        </div>
      </section>
    </div>
  `,
  styles: `
    pre { max-height: 280px; overflow: auto; padding: 14px; border-radius: 12px; background: #071018; color: var(--muted); white-space: pre-wrap; }
  `,
})
export class WorkersPageComponent implements OnInit, OnDestroy {
  private readonly api = inject(ApiService);
  private readonly auth = inject(AuthService);
  private readonly zone = inject(NgZone);
  readonly worker = signal<WorkerStatus | null>(null);
  readonly jobs = signal<BackgroundJob[]>([]);
  readonly logs = signal<WorkerLogs | null>(null);
  readonly message = signal('');
  jobStatus = '';
  private timer: ReturnType<typeof setTimeout> | null = null;

  ngOnInit() {
    this.load();
    if (this.isAdmin()) this.loadLogs();
  }

  isAdmin() { return this.auth.user()?.role === 'admin'; }

  load() {
    this.api.workerStatus().subscribe({
      next: (status) => this.worker.set(status),
      error: () => this.message.set('Impossible de lire le statut du worker.'),
    });
    this.loadJobs();
    if (this.timer) clearTimeout(this.timer);
    this.zone.runOutsideAngular(() => {
      this.timer = setTimeout(() => this.zone.run(() => this.load()), 3000);
    });
  }

  loadJobs() {
    this.api.backgroundJobs({ status: this.jobStatus }).subscribe((data) => this.jobs.set(data.results));
  }

  start() {
    this.message.set('Démarrage demandé...');
    this.api.startWorker().subscribe({
      next: (status) => {
        this.worker.set(status);
        this.message.set(status.already_running ? 'Le worker est déjà actif.' : 'Worker en cours de démarrage.');
        setTimeout(() => this.load(), 1000);
      },
      error: (error) => this.message.set(error?.error?.detail || 'Impossible de démarrer le worker.'),
    });
  }

  retry(job: BackgroundJob) {
    this.api.retryBackgroundJob(job.id).subscribe({
      next: () => {
        this.message.set('Job replacé dans la file.');
        this.loadJobs();
      },
      error: () => this.message.set('Relance impossible.'),
    });
  }

  cancel(job: BackgroundJob) {
    this.api.cancelBackgroundJob(job.id).subscribe({
      next: () => {
        this.message.set(job.status === 'queued' ? 'Job annulé.' : 'Arrêt demandé au job en cours.');
        this.loadJobs();
      },
      error: (error) => this.message.set(error?.error?.detail || 'Arrêt impossible.'),
    });
  }

  loadLogs() {
    this.api.workerLogs().subscribe({
      next: (logs) => this.logs.set(logs),
      error: () => this.message.set('Impossible de lire les logs du worker.'),
    });
  }

  ngOnDestroy() { if (this.timer) clearTimeout(this.timer); }
}
