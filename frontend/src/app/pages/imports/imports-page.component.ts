import { Component, OnDestroy, OnInit, inject, signal } from '@angular/core';
import { DatePipe } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ApiService } from '../../core/api/api.service';
import { FlowImport, Structure } from '../../core/api/api.types';
import { formatBytes } from '../../shared/formatters';

@Component({
  selector: 'app-imports-page',
  standalone: true,
  imports: [DatePipe, FormsModule],
  template: `
    <div class="page">
      <div class="page-title">
        <div>
          <h1>Imports CSV</h1>
          <p>Ajouter un export SNA/Stealthwatch et suivre les imports existants.</p>
        </div>
        <button class="btn secondary" (click)="load()">Rafraîchir</button>
      </div>

      <section class="card">
        <h2>Upload CSV</h2>
        <div class="toolbar">
          <label class="field">
            <span>Structure</span>
            <select class="select" [(ngModel)]="structureId">
              @for (structure of structures(); track structure.id) {
                <option [ngValue]="structure.id">{{ structure.code }} — {{ structure.name }}</option>
              }
            </select>
          </label>
          <label class="field">
            <span>Fichier CSV</span>
            <input class="input" type="file" accept=".csv,text/csv" (change)="selectFile($event)" />
          </label>
          <button class="btn" (click)="preview()" [disabled]="!file() || !structureId">Prévalider</button>
          @if (previewImportId()) {
            <button class="btn secondary" (click)="confirm()">Confirmer import #{{ previewImportId() }}</button>
          }
        </div>
        @if (message()) {
          <p class="muted">{{ message() }}</p>
        }
      </section>

      <section class="card">
        <h2>Liste des imports</h2>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>ID</th>
                <th>Structure</th>
                <th>Status</th>
                <th>Fichier</th>
                <th>Taille</th>
                <th>Lignes</th>
                <th>Acceptées</th>
                <th>Rejetées</th>
                <th>Progression</th>
                <th>Date import</th>
                <th>Début flows</th>
                <th>Fin flows</th>
              </tr>
            </thead>
            <tbody>
              @for (item of imports(); track item.id) {
                <tr>
                  <td>#{{ item.id }}</td>
                  <td>{{ structureLabel(item.structure) }}</td>
                  <td><span class="badge" [class.success]="item.status === 'completed'" [class.warning]="item.status.includes('errors')" [class.danger]="item.status === 'failed'">{{ item.status }}</span></td>
                  <td>{{ item.original_filename }}</td>
                  <td>{{ bytes(item.file_size_bytes) }}</td>
                  <td>{{ item.total_rows }}</td>
                  <td>{{ item.accepted_rows }}</td>
                  <td>{{ item.rejected_rows }}</td>
                  <td>{{ jobProgress(item) }}</td>
                  <td>{{ item.uploaded_at | date:'medium' }}</td>
                  <td>{{ item.period_start ? (item.period_start | date:'medium') : '-' }}</td>
                  <td>{{ item.period_end ? (item.period_end | date:'medium') : '-' }}</td>
                </tr>
              } @empty {
                <tr><td colspan="12"><div class="empty">Aucun import.</div></td></tr>
              }
            </tbody>
          </table>
        </div>
      </section>
    </div>
  `,
})
export class ImportsPageComponent implements OnInit, OnDestroy {
  private readonly api = inject(ApiService);
  readonly imports = signal<FlowImport[]>([]);
  readonly structures = signal<Structure[]>([]);
  readonly file = signal<File | null>(null);
  readonly message = signal('');
  readonly previewImportId = signal<number | null>(null);
  readonly bytes = formatBytes;
  structureId = 0;
  private pollTimer: ReturnType<typeof setTimeout> | null = null;

  ngOnInit() {
    this.load();
    this.api.structures({ is_active: true }).subscribe((data) => {
      this.structures.set(data.results);
      if (data.results.length) {
        this.structureId = data.results[0].id;
      }
    });
  }

  load() {
    this.api.imports().subscribe((data) => {
      this.imports.set(data.results);
      const active = data.results.find((item) => ['queued', 'running'].includes(item.latest_job?.status || ''));
      if (active?.latest_job) {
        this.poll(active.latest_job.id);
      }
    });
  }

  selectFile(event: Event) {
    const input = event.target as HTMLInputElement;
    this.file.set(input.files?.[0] ?? null);
    this.previewImportId.set(null);
  }

  preview() {
    const file = this.file();
    if (!file) return;
    this.message.set('Prévalidation en cours...');
    this.api.previewImport(this.structureId, file).subscribe({
      next: (result: any) => {
        this.previewImportId.set(result.import_id);
        if (result.is_valid) {
          const networks = (result.network_detection?.networks || [])
            .map((item: any) => `${item.name}: ${item.sample_rows}`)
            .join(', ');
          const rejected = result.network_detection?.sample_rejections?.length || 0;
          this.message.set(`Prévalidation OK. Réseaux détectés dans l'échantillon : ${networks || 'aucun'}${rejected ? `; ${rejected} ligne(s) non classée(s)` : ''}. Tu peux confirmer.`);
        } else {
          const missing = result.errors?.[0]?.columns?.join(', ') || '-';
          this.message.set(`Prévalidation avec erreurs. Colonnes manquantes : ${missing}`);
        }
        this.load();
      },
      error: (error) => this.message.set(this.errorMessage(error, 'Erreur pendant la prévalidation.')),
    });
  }

  confirm() {
    const id = this.previewImportId();
    if (!id) return;
    this.message.set('Import en cours...');
    this.api.confirmImport(id).subscribe({
      next: (response) => {
        this.message.set(response.already_queued ? 'Import déjà en file.' : 'Import ajouté à la file.');
        this.previewImportId.set(null);
        this.load();
        this.poll(response.job.id);
      },
      error: (error) => this.message.set(this.errorMessage(error, 'Erreur pendant la confirmation.')),
    });
  }

  jobProgress(item: FlowImport): string {
    const job = item.latest_job;
    if (!job) return '-';
    if (job.status === 'failed') return `Échec : ${job.error_message}`;
    if (job.progress_percent !== null) return `${job.status} — ${job.progress_percent}%`;
    if (job.progress_current) return `${job.status} — ${job.progress_current} ligne(s)`;
    return job.status_message || job.status;
  }

  private poll(jobId: string) {
    if (this.pollTimer) clearTimeout(this.pollTimer);
    this.pollTimer = setTimeout(() => {
      this.api.backgroundJob(jobId).subscribe({
        next: (job) => {
          this.message.set(job.status === 'failed' ? `Échec : ${job.error_message}` : job.status_message || job.status);
          this.load();
          if (job.status === 'queued' || job.status === 'running') this.poll(job.id);
        },
      });
    }, 1500);
  }

  ngOnDestroy() {
    if (this.pollTimer) clearTimeout(this.pollTimer);
  }

  private errorMessage(error: any, fallback: string): string {
    const body = error?.error;
    if (body?.detail) {
      return body.detail;
    }
    if (body?.file?.length) {
      return `Fichier : ${body.file.join(', ')}`;
    }
    if (body?.structure_id?.length) {
      return `Structure : ${body.structure_id.join(', ')}`;
    }
    return fallback;
  }

  structureLabel(id: number): string {
    const structure = this.structures().find((item) => item.id === id);
    return structure ? `${structure.code} — ${structure.name}` : `#${id}`;
  }
}
