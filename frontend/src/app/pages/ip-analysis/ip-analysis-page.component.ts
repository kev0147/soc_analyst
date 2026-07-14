import { DatePipe } from '@angular/common';
import { Component, OnDestroy, OnInit, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ApiService } from '../../core/api/api.service';
import { IpAnalysisRecord } from '../../core/api/api.types';

@Component({
  selector: 'app-ip-analysis-page',
  standalone: true,
  imports: [DatePipe, FormsModule],
  template: `
    <div class="page">
      <div class="page-title">
        <div>
          <h1>Analyse IP</h1>
          <p>AbuseIPDB, VirusTotal et Shodan — priorité aux IP jamais analysées.</p>
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
              <label><input type="checkbox" [(ngModel)]="tools.shodan" /> Shodan</label>
            </div>
            <button class="btn" (click)="run()">Lancer</button>
            @if (message()) {
              <p class="muted">{{ message() }}</p>
            }
          </div>
        </article>

        <article class="card">
          <h2>Priorité d’analyse</h2>
          <ol class="muted">
            <li>IP jamais analysées</li>
            <li>IP analysées par 1 plateforme</li>
            <li>IP analysées par 2 plateformes</li>
            <li>IP déjà analysées par les 3 plateformes</li>
          </ol>
          <p class="muted">Ce tri sera exécuté côté backend réputation IP.</p>
        </article>
      </section>

      <section class="card">
        <h2>Adresses IP analysées</h2>
        <div class="toolbar">
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
                <th>Shodan</th>
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
                  <td>{{ sourceLabel(record, 'shodan') }}</td>
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
  readonly message = signal('');
  readonly records = signal<IpAnalysisRecord[]>([]);
  scope: 'all_flows' | 'import' = 'all_flows';
  importId: number | null = null;
  verdict = '';
  ipFilter = '';
  tools = {
    abuseipdb: true,
    virustotal: true,
    shodan: true,
  };
  private pollTimer: ReturnType<typeof setTimeout> | null = null;

  ngOnInit() {
    this.load();
  }

  run() {
    const selectedTools = Object.entries(this.tools)
      .filter(([, enabled]) => enabled)
      .map(([name]) => name);
    this.api.launchIpAnalysis({ scope: this.scope, import_id: this.importId ?? undefined, tools: selectedTools }).subscribe({
      next: (response) => {
        this.message.set(response.already_queued ? 'Cette analyse est déjà en file.' : 'Analyse ajoutée à la file.');
        this.poll(response.job.id);
      },
      error: () => this.message.set('Analyse impossible. Vérifie que le backend tourne et que les clés API sont configurées.'),
    });
  }

  private poll(jobId: string) {
    if (this.pollTimer) clearTimeout(this.pollTimer);
    this.pollTimer = setTimeout(() => {
      this.api.backgroundJob(jobId).subscribe({
        next: (job) => {
          const progress = job.progress_percent === null ? job.progress_current : `${job.progress_percent}%`;
          this.message.set(job.status === 'failed' ? `Échec : ${job.error_message}` : `${job.status_message || job.status}${progress ? ` — ${progress}` : ''}`);
          if (job.status === 'completed') this.load();
          if (job.status === 'queued' || job.status === 'running') this.poll(job.id);
        },
        error: () => this.message.set('Impossible de suivre le job.'),
      });
    }, 1500);
  }

  ngOnDestroy() {
    if (this.pollTimer) clearTimeout(this.pollTimer);
  }

  load() {
    this.api.ipAnalysisRecords({ verdict: this.verdict, ip: this.ipFilter }).subscribe({
      next: (data) => {
        this.records.set(data.results);
        this.message.set(`${data.count} résultat(s).`);
      },
      error: () => this.message.set('Chargement impossible. Vérifie que le backend tourne.'),
    });
  }

  sourceLabel(record: IpAnalysisRecord, source: 'abuseipdb' | 'virustotal' | 'shodan'): string {
    const item = record.results.find((result) => result.source === source);
    if (!item) {
      return '-';
    }
    const score = item.score === null || item.score === undefined ? '-' : item.score;
    return `${item.verdict} (${score})`;
  }
}
