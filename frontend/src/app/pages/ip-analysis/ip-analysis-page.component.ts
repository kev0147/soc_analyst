import { DatePipe } from '@angular/common';
import { Component, NgZone, OnDestroy, OnInit, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ApiService } from '../../core/api/api.service';
import { IpAnalysisRecord, IpReputationSourceState, Structure } from '../../core/api/api.types';

@Component({
  selector: 'app-ip-analysis-page',
  standalone: true,
  imports: [DatePipe, FormsModule],
  template: `
    <div class="page">
      <div class="page-title">
        <div>
          <h1>Analyse IP</h1>
          <p>Réputation AbuseIPDB et VirusTotal — priorité aux résultats absents ou expirés.</p>
        </div>
      </div>

      <section class="grid cols-2">
        <article class="card">
          <h2>Lancer une analyse</h2>
          <div class="grid">
            <label class="field">
              <span>Périmètre</span>
              <select class="select" [(ngModel)]="scope">
                <option value="all_flows">Tous les flows</option>
                <option value="import">Un import</option>
              </select>
            </label>
            @if (scope === 'import') {
              <label class="field">
                <span>ID import</span>
                <input class="input" type="number" [(ngModel)]="importId" />
              </label>
            }
            <div class="toolbar">
              <label><input type="checkbox" [(ngModel)]="tools.abuseipdb" /> AbuseIPDB</label>
              <label><input type="checkbox" [(ngModel)]="tools.virustotal" /> VirusTotal</label>
              <label><input type="checkbox" [(ngModel)]="forceRefresh" /> Forcer l'actualisation des résultats encore frais</label>
            </div>
            <button class="btn" (click)="run()">Lancer</button>
            @if (message()) {
              <p class="muted">{{ message() }}</p>
            }
            <label class="field">
              <span>Nombre maximal d’IP à analyser</span>
              <input class="input" type="number" min="1" max="500" [(ngModel)]="limit" />
            </label>
            @if (lastRunSummary()) {
              <p class="badge info">{{ lastRunSummary() }}</p>
            }
          </div>
        </article>

        <article class="card">
          <h2>Priorité d’analyse</h2>
          <ol class="muted">
            <li>IP jamais analysées</li>
            <li>Plateforme manquante pour une IP partiellement analysée</li>
            <li>Résultats arrivés à expiration</li>
            <li>Résultats encore frais uniquement si l'actualisation est forcée</li>
          </ol>
          <p class="muted">Par défaut, aucune requête API n'est répétée pour un résultat encore frais.</p>
        </article>
      </section>

      <section class="grid cols-2">
        @for (source of sourceStates(); track source.source) {
          <article class="card">
            <h3>{{ source.source === 'abuseipdb' ? 'AbuseIPDB' : 'VirusTotal' }}</h3>
            @if (source.quota_exhausted) {
              <p><span class="badge danger">Quota épuisé</span></p>
              <p class="muted">Cette plateforme est suspendue jusqu’au {{ source.quota_exhausted_until | date:'medium' }}. Les autres plateformes continuent.</p>
            } @else {
              <p><span class="badge success">Disponible</span></p>
            }
            @if (source.last_error_message) { <p class="muted">{{ source.last_error_message }}</p> }
          </article>
        }
      </section>

      <section class="card">
        <h2>Adresses IP analysées</h2>
        <div class="toolbar">
          <select class="select" [(ngModel)]="structureId">
            <option [ngValue]="null">Toutes les structures</option>
            @for (structure of structures(); track structure.id) {
              <option [ngValue]="structure.id">{{ structure.name }}</option>
            }
          </select>
          <input class="input" [(ngModel)]="ipFilter" placeholder="Filtrer par IP" />
          <select class="select" [(ngModel)]="verdict">
            <option value="">Toutes</option>
            <option value="malicious">Malveillantes</option>
            <option value="suspicious">Suspectes</option>
            <option value="clean">Propres</option>
            <option value="unknown">Inconnues</option>
          </select>
          <button class="btn secondary" (click)="load()">Charger</button>
        </div>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>IP</th>
                <th>Pays</th>
                <th>Verdict</th>
                <th>Score</th>
                <th>Flows</th>
                <th>AbuseIPDB</th>
                <th>VirusTotal</th>
                <th>Fraîcheur</th>
                <th>Dernière analyse</th>
              </tr>
            </thead>
            <tbody>
              @for (record of records(); track record.id) {
                <tr>
                  <td>{{ record.ip_address }}</td>
                  <td>{{ record.country || '-' }}</td>
                  <td>
                    <span class="badge"
                      [class.danger]="record.verdict === 'malicious'"
                      [class.warning]="record.verdict === 'suspicious'"
                      [class.success]="record.verdict === 'clean'"
                    >
                      {{ record.verdict }}
                    </span>
                  </td>
                  <td>{{ record.score ?? '-' }}</td>
                  <td>{{ record.flow_count }}</td>
                  <td>{{ sourceLabel(record, 'abuseipdb') }}</td>
                  <td>{{ sourceLabel(record, 'virustotal') }}</td>
                  <td>{{ record.freshness_status }}</td>
                  <td>{{ record.last_analyzed_at ? (record.last_analyzed_at | date:'medium') : '-' }}</td>
                </tr>
              } @empty {
                <tr>
                  <td colspan="9">
                    <div class="empty">Aucune adresse IP analysée pour le moment.</div>
                  </td>
                </tr>
              }
            </tbody>
          </table>
        </div>
      </section>
    </div>
  `,
})
export class IpAnalysisPageComponent implements OnInit, OnDestroy {
  private readonly api = inject(ApiService);
  private readonly zone = inject(NgZone);
  readonly message = signal('');
  readonly lastRunSummary = signal('');
  readonly records = signal<IpAnalysisRecord[]>([]);
  readonly structures = signal<Structure[]>([]);
  readonly sourceStates = signal<IpReputationSourceState[]>([]);
  scope: 'all_flows' | 'import' = 'all_flows';
  importId: number | null = null;
  structureId: number | null = null;
  verdict = '';
  ipFilter = '';
  tools = {
    abuseipdb: true,
    virustotal: true,
  };
  forceRefresh = false;
  limit = 10;
  private pollTimer: ReturnType<typeof setTimeout> | null = null;

  ngOnInit() {
    this.api.structures().subscribe((data) => this.structures.set(data.results));
    this.loadSourceStates();
    this.load();
  }

  run() {
    const selectedTools = Object.entries(this.tools)
      .filter(([, enabled]) => enabled)
      .map(([name]) => name);
    this.api.launchIpAnalysis({
      scope: this.scope,
      import_id: this.importId ?? undefined,
      tools: selectedTools,
      limit: Math.min(Math.max(this.limit || 1, 1), 500),
      force_refresh: this.forceRefresh,
    }).subscribe({
      next: (response) => {
        this.message.set(response.already_queued ? 'Cette analyse est déjà en file.' : 'Analyse ajoutée à la file.');
        this.poll(response.job.id);
      },
      error: () => this.message.set('Analyse impossible. Vérifie que le backend tourne et que les clés API sont configurées.'),
    });
  }

  private poll(jobId: string) {
    if (this.pollTimer) clearTimeout(this.pollTimer);
    this.zone.runOutsideAngular(() => {
      this.pollTimer = setTimeout(() => this.zone.run(() => {
        this.api.backgroundJob(jobId).subscribe({
        next: (job) => {
          const progress = job.progress_percent === null ? job.progress_current : `${job.progress_percent}%`;
          this.message.set(job.status === 'failed' ? `Échec : ${job.error_message}` : `${job.status_message || job.status}${progress ? ` — ${progress}` : ''}`);
          if (job.status === 'completed') {
            const result = job.result as Record<string, any>;
            const counts = (result['source_analysis_counts'] || {}) as Record<string, number>;
            const candidates = Number(result['candidate_count'] || 0);
            this.lastRunSummary.set(
              `Analyse terminée : ${candidates} IP candidate(s), `
              + `${counts['abuseipdb'] || 0} appel(s) AbuseIPDB, `
              + `${counts['virustotal'] || 0} appel(s) VirusTotal.`
              + (candidates === 0 ? ' Les résultats sont probablement encore frais ; coche « Forcer l’actualisation » pour les interroger à nouveau.' : '')
            );
            this.load();
            this.loadSourceStates();
          }
          if (job.status === 'queued' || job.status === 'running') this.poll(job.id);
        },
        error: () => this.message.set('Impossible de suivre le job.'),
        });
      }), 3000);
    });
  }

  ngOnDestroy() {
    if (this.pollTimer) clearTimeout(this.pollTimer);
  }

  load() {
    this.api.ipAnalysisRecords({
      structure_id: this.structureId,
      verdict: this.verdict,
      ip: this.ipFilter,
    }).subscribe({
      next: (data) => {
        this.records.set(data.results);
        this.message.set(`${data.count} résultat(s).`);
      },
      error: () => this.message.set('Chargement impossible. Vérifie que le backend tourne.'),
    });
  }

  private loadSourceStates() {
    this.api.ipAnalysisSourceStates().subscribe({
      next: (data) => this.sourceStates.set(data.results),
      error: () => this.message.set('Impossible de charger l’état des quotas API.'),
    });
  }

  sourceLabel(record: IpAnalysisRecord, source: 'abuseipdb' | 'virustotal'): string {
    const item = record.results.find((result) => result.source === source);
    if (!item) {
      return '-';
    }
    if (item.freshness_status === 'never_analyzed') return 'Jamais analysé';
    const score = item.score === null || item.score === undefined ? '-' : item.score;
    const freshness = item.is_stale ? 'expiré' : 'frais';
    return `${item.verdict} (${score}) — ${freshness}`;
  }
}
