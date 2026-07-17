import { DatePipe } from '@angular/common';
import { Component, OnInit, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ApiService, QueryParams } from '../../core/api/api.service';
import {
  FlowImport,
  MaliciousCommunicationAnalysis,
  Structure,
} from '../../core/api/api.types';
import { formatBytes, formatDuration } from '../../shared/formatters';

@Component({
  selector: 'app-analysis-page',
  standalone: true,
  imports: [DatePipe, FormsModule],
  template: `
    <div class="page">
      <div class="page-title">
        <div>
          <h1>Analyse SOC</h1>
          <p>Corréler les hôtes avec les IP malveillantes observées dans un périmètre précis.</p>
        </div>
      </div>

      <section class="card filters">
        <label class="field">
          <span>Périmètre</span>
          <select class="select" [(ngModel)]="scope">
            <option value="structure">Une structure</option>
            <option value="import">Un import</option>
            <option value="date_range">Un intervalle de dates</option>
          </select>
        </label>
        @if (scope === 'structure') {
          <label class="field">
            <span>Structure</span>
            <select class="select" [(ngModel)]="structureId">
              @for (structure of structures(); track structure.id) {
                <option [ngValue]="structure.id">{{ structure.code }} — {{ structure.name }}</option>
              }
            </select>
          </label>
        }
        @if (scope === 'import') {
          <label class="field">
            <span>Import</span>
            <select class="select" [(ngModel)]="importId">
              @for (item of imports(); track item.id) {
                <option [ngValue]="item.id">#{{ item.id }} — {{ item.original_filename }}</option>
              }
            </select>
          </label>
        }
        @if (scope === 'date_range') {
          <label class="field">
            <span>Début</span>
            <input class="input" type="datetime-local" [(ngModel)]="dateFrom" />
          </label>
          <label class="field">
            <span>Fin</span>
            <input class="input" type="datetime-local" [(ngModel)]="dateTo" />
          </label>
        }
        <label class="field">
          <span>IP hôte</span>
          <input class="input" [(ngModel)]="hostIp" placeholder="IP exacte" />
        </label>
        <label class="field">
          <span>IP malveillante</span>
          <input class="input" [(ngModel)]="peerIp" placeholder="IP exacte" />
        </label>
        <label class="field">
          <span>Pays du peer</span>
          <input class="input" [(ngModel)]="country" placeholder="FR, Canada, France..." />
        </label>
        <label class="field">
          <span>Port de l’hôte</span>
          <input class="input" type="number" [(ngModel)]="hostPort" />
        </label>
        <label class="field">
          <span>Trafic minimum (octets)</span>
          <input class="input" type="number" [(ngModel)]="minBytes" />
        </label>
        <label class="field">
          <span>Durée minimum (secondes)</span>
          <input class="input" type="number" [(ngModel)]="minDuration" />
        </label>
        <label class="field">
          <span>Classement</span>
          <select class="select" [(ngModel)]="ordering">
            <option value="-total_bytes">Plus gros trafic</option>
            <option value="-total_duration_seconds">Plus longue durée</option>
            <option value="-flow_count">Plus grand nombre de flows</option>
            <option value="-reputation_score">Score de réputation</option>
            <option value="-last_seen_at">Plus récemment observés</option>
            <option value="host_ip">IP hôte croissante</option>
          </select>
        </label>
        <button class="btn" (click)="analyze()">Analyser</button>
      </section>

      @if (message()) {
        <p class="muted">{{ message() }}</p>
      }

      @if (analysis(); as data) {
        <section class="grid cols-3">
          <article class="card metric"><span>Hôtes</span><strong>{{ data.totals.hosts }}</strong></article>
          <article class="card metric"><span>IP malveillantes</span><strong>{{ data.totals.malicious_peers }}</strong></article>
          <article class="card metric"><span>Corrélations hôte / peer</span><strong>{{ data.totals.correlations }}</strong></article>
          <article class="card metric"><span>Flows corrélés</span><strong>{{ data.totals.flows }}</strong></article>
          <article class="card metric"><span>Trafic cumulé</span><strong>{{ bytes(data.totals.total_bytes) }}</strong></article>
          <article class="card metric"><span>Durée cumulée</span><strong>{{ duration(data.totals.total_duration_seconds) }}</strong></article>
        </section>

        <section class="card">
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Hôte</th>
                  <th>Ports hôte ciblés/observés</th>
                  <th>IP malveillante</th>
                  <th>Réputation</th>
                  <th>Pays du peer</th>
                  <th>Flows</th>
                  <th>Trafic cumulé</th>
                  <th>Durée cumulée</th>
                  <th>Dernière observation</th>
                </tr>
              </thead>
              <tbody>
                @for (row of data.results; track row.host_ip + '-' + row.malicious_ip) {
                  <tr>
                    <td>{{ row.host_ip }}</td>
                    <td>{{ row.host_ports.join(', ') || '-' }}</td>
                    <td>{{ row.malicious_ip }}</td>
                    <td><span class="badge danger">{{ row.reputation_verdict }} · {{ row.reputation_score ?? '-' }}</span></td>
                    <td>{{ row.peer_country || 'Non renseigné' }}</td>
                    <td>{{ row.flow_count }}</td>
                    <td>{{ bytes(row.total_bytes) }}</td>
                    <td>{{ duration(row.total_duration_seconds) }}</td>
                    <td>{{ row.last_seen_at ? (row.last_seen_at | date:'medium') : '-' }}</td>
                  </tr>
                } @empty {
                  <tr><td colspan="9"><div class="empty">Aucune communication avec une IP malveillante dans ce périmètre.</div></td></tr>
                }
              </tbody>
            </table>
          </div>
        </section>
      }
    </div>
  `,
  styles: `
    .metric span { color: var(--muted); }
    .metric strong { display: block; margin-top: 8px; font-size: 28px; }
  `,
})
export class AnalysisPageComponent implements OnInit {
  private readonly api = inject(ApiService);
  readonly structures = signal<Structure[]>([]);
  readonly imports = signal<FlowImport[]>([]);
  readonly analysis = signal<MaliciousCommunicationAnalysis | null>(null);
  readonly message = signal('');
  readonly bytes = formatBytes;
  readonly duration = formatDuration;

  scope: 'structure' | 'import' | 'date_range' = 'structure';
  structureId = 0;
  importId = 0;
  dateFrom = '';
  dateTo = '';
  hostIp = '';
  peerIp = '';
  country = '';
  hostPort: number | null = null;
  minBytes: number | null = null;
  minDuration: number | null = null;
  ordering = '-total_bytes';

  ngOnInit() {
    this.api.structures({ is_active: true }).subscribe((data) => {
      this.structures.set(data.results);
      this.structureId = data.results[0]?.id || 0;
    });
    this.api.imports().subscribe((data) => {
      this.imports.set(data.results);
      this.importId = data.results[0]?.id || 0;
    });
  }

  analyze() {
    const params: QueryParams = {
      scope: this.scope,
      ordering: this.ordering,
      host_ip: this.hostIp,
      peer_ip: this.peerIp,
      country: this.country,
      host_port: this.hostPort,
      min_total_bytes: this.minBytes,
      min_total_duration_seconds: this.minDuration,
    };
    if (this.scope === 'structure') params['structure_id'] = this.structureId;
    if (this.scope === 'import') params['import_id'] = this.importId;
    if (this.scope === 'date_range') {
      params['date_from'] = this.normalizedDate(this.dateFrom);
      params['date_to'] = this.normalizedDate(this.dateTo);
    }

    this.message.set('Analyse en cours...');
    this.api.maliciousCommunications(params).subscribe({
      next: (result) => {
        this.analysis.set(result);
        this.message.set(`${result.count} corrélation(s) hôte / IP malveillante.`);
      },
      error: (error) => {
        const detail = error?.error;
        const first = detail && typeof detail === 'object' ? Object.values(detail)[0] : null;
        this.message.set(Array.isArray(first) ? String(first[0]) : String(first || 'Analyse impossible.'));
      },
    });
  }

  private normalizedDate(value: string): string {
    return value && value.length === 16 ? `${value}:00` : value;
  }
}
