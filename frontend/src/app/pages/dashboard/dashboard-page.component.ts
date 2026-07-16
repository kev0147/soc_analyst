import { Component, OnInit, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ApiService } from '../../core/api/api.service';
import { DashboardOverview, Structure } from '../../core/api/api.types';
import { formatBytes, formatDuration } from '../../shared/formatters';

@Component({
  selector: 'app-dashboard-page',
  standalone: true,
  imports: [FormsModule],
  template: `
    <div class="page">
      <div class="page-title">
        <div>
          <h1>Dashboard</h1>
          <p>Vue d’ensemble des communications, volumes, imports et bulletins.</p>
        </div>
        <div class="toolbar">
          <label class="field">
            <span>Structure</span>
            <select class="select" [(ngModel)]="structureId" (ngModelChange)="load()">
              <option [ngValue]="null">Toutes les structures</option>
              @for (structure of structures(); track structure.id) {
                <option [ngValue]="structure.id">{{ structure.code }} — {{ structure.name }}</option>
              }
            </select>
          </label>
          <button class="btn secondary" (click)="load()">Rafraîchir</button>
        </div>
      </div>

      @if (dashboard(); as data) {
        <section class="grid cols-3">
          <article class="card metric">
            <span>Flows</span>
            <strong>{{ data.totals.flows }}</strong>
          </article>
          <article class="card metric">
            <span>Traffic</span>
            <strong>{{ bytes(data.totals.total_bytes) }}</strong>
          </article>
          <article class="card metric">
            <span>Bulletins</span>
            <strong>{{ data.totals.bulletins }}</strong>
          </article>
        </section>

        <section class="grid cols-2">
          <article class="card">
            <h2>IP malveillantes — volume</h2>
            @for (row of data.top_malicious_ips_by_volume; track row.ip_address) {
              <div class="row">
                <span>
                  {{ row.ip_address }} <span class="muted">{{ row.country || '' }}</span><br />
                  <small>{{ row.flow_count }} flow(s) · {{ duration(row.total_duration_seconds) }}</small>
                </span>
                <strong>{{ bytes(row.total_bytes) }}</strong>
              </div>
            } @empty {
              <div class="empty">Aucune communication malveillante connue.</div>
            }
          </article>

          <article class="card">
            <h2>IP malveillantes — durée</h2>
            @for (row of data.top_malicious_ips_by_duration; track row.ip_address) {
              <div class="row">
                <span>
                  {{ row.ip_address }} <span class="muted">{{ row.country || '' }}</span><br />
                  <small>{{ row.flow_count }} flow(s) · {{ bytes(row.total_bytes) }}</small>
                </span>
                <strong>{{ duration(row.total_duration_seconds) }}</strong>
              </div>
            } @empty {
              <div class="empty">Aucune communication malveillante connue.</div>
            }
          </article>

          <article class="card">
            <h2>Hôtes exposés — volume</h2>
            @for (row of data.top_hosts_with_malicious_by_volume; track row.host_ip) {
              <div class="row">
                <span>
                  {{ row.host_ip }}<br />
                  <small>{{ row.malicious_peer_count }} peer(s) malveillant(s) · {{ row.flow_count }} flow(s)</small>
                </span>
                <strong>{{ bytes(row.total_bytes) }}</strong>
              </div>
            } @empty {
              <div class="empty">Aucun hôte en contact avec une IP malveillante.</div>
            }
          </article>

          <article class="card">
            <h2>Hôtes exposés — durée</h2>
            @for (row of data.top_hosts_with_malicious_by_duration; track row.host_ip) {
              <div class="row">
                <span>
                  {{ row.host_ip }}<br />
                  <small>{{ row.malicious_peer_count }} peer(s) malveillant(s) · {{ bytes(row.total_bytes) }}</small>
                </span>
                <strong>{{ duration(row.total_duration_seconds) }}</strong>
              </div>
            } @empty {
              <div class="empty">Aucun hôte en contact avec une IP malveillante.</div>
            }
          </article>
        </section>

        <section class="grid cols-3">
          <article class="card">
            <h2>Top talkers</h2>
            @for (row of data.top_talkers; track row['ip']) {
              <div class="row">
                <span>{{ row['ip'] }}</span>
                <strong>{{ bytes(+row['total_bytes']!) }}</strong>
              </div>
            } @empty {
              <div class="empty">Aucune donnée.</div>
            }
          </article>
          <article class="card">
            <h2>Top conversations</h2>
            @for (row of data.top_conversations; track row['conversation_ip_a'] + '-' + row['conversation_ip_b']) {
              <div class="row">
                <span>{{ row['conversation_ip_a'] }} ⇄ {{ row['conversation_ip_b'] }}</span>
                <strong>{{ bytes(+row['total_bytes']!) }}</strong>
              </div>
            } @empty {
              <div class="empty">Aucune donnée.</div>
            }
          </article>
          <article class="card">
            <h2>10 dernières IP malveillantes</h2>
            @for (row of data.latest_malicious_ips || []; track row['ip_address']) {
              <div class="row">
                <span>{{ row['ip_address'] }} <span class="muted">{{ row['country'] || '' }}</span></span>
                <strong>{{ row['score'] ?? '-' }}</strong>
              </div>
            } @empty {
              <div class="empty">Aucune IP malveillante connue.</div>
            }
          </article>
        </section>
      } @else {
        <div class="empty">Chargement du dashboard...</div>
      }
    </div>
  `,
  styles: `
    .metric span {
      color: var(--muted);
    }
    .metric strong {
      display: block;
      margin-top: 8px;
      font-size: 34px;
    }
    .row {
      display: flex;
      justify-content: space-between;
      gap: 12px;
      padding: 10px 0;
      border-bottom: 1px solid var(--line);
    }
    .row span {
      color: var(--muted);
      overflow-wrap: anywhere;
    }
    .network-figure {
      height: 180px;
      display: grid;
      grid-template-columns: 1fr 100px 1fr;
      align-items: center;
    }
    .node {
      display: grid;
      place-items: center;
      min-height: 90px;
      border-radius: 18px;
      border: 1px solid var(--line);
      background: var(--panel-2);
      text-align: center;
      padding: 12px;
    }
    .bad {
      border-color: rgba(239, 68, 68, 0.4);
      color: #fecaca;
    }
    .links {
      height: 2px;
      background: linear-gradient(90deg, var(--brand), var(--danger));
    }
  `,
})
export class DashboardPageComponent implements OnInit {
  private readonly api = inject(ApiService);
  readonly dashboard = signal<DashboardOverview | null>(null);
  readonly structures = signal<Structure[]>([]);
  readonly bytes = formatBytes;
  readonly duration = formatDuration;
  structureId: number | null = null;

  ngOnInit() {
    this.api.structures({ is_active: true }).subscribe((data) => this.structures.set(data.results));
    this.load();
  }

  load() {
    this.api.dashboard({ limit: 10, structure_id: this.structureId }).subscribe((data) => this.dashboard.set(data));
  }
}
