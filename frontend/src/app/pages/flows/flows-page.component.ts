import { DatePipe } from '@angular/common';
import { Component, OnInit, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ApiService, QueryParams } from '../../core/api/api.service';
import { Flow, Structure } from '../../core/api/api.types';
import { formatBytes, formatDuration } from '../../shared/formatters';

interface FlowFilters extends QueryParams {
  structure_id: number | null;
  ordering: string;
  date_from: string;
  date_to: string;
  ip: string;
  peer_ip: string;
  port: number | null;
  service: string;
  min_duration: number | null;
  min_total_bytes: number | null;
  peer_verdict: string;
}

@Component({
  selector: 'app-flows-page',
  standalone: true,
  imports: [DatePipe, FormsModule],
  template: `
    <div class="page">
      <div class="page-title">
        <div>
          <h1>Flows</h1>
          <p>Communications chronologiques, filtrables par période, ports, hôtes, peers, durée et trafic.</p>
        </div>
        <a class="btn secondary" [href]="exportUrl()">Exporter CSV</a>
      </div>

      <section class="card filters">
        <label class="field">
          <span>Structure</span>
          <select class="select" [(ngModel)]="filters.structure_id">
            <option [ngValue]="null">Toutes les structures</option>
            @for (structure of structures(); track structure.id) {
              <option [ngValue]="structure.id">{{ structure.name }}</option>
            }
          </select>
        </label>
        <label class="field">
          <span>Début période</span>
          <input class="input" type="datetime-local" [(ngModel)]="filters.date_from" />
        </label>
        <label class="field">
          <span>Fin période</span>
          <input class="input" type="datetime-local" [(ngModel)]="filters.date_to" />
        </label>
        <label class="field">
          <span>IP host/peer</span>
          <input class="input" [(ngModel)]="filters.ip" placeholder="ex: 203.0.113.10" />
        </label>
        <label class="field">
          <span>Peer IP</span>
          <input class="input" [(ngModel)]="filters.peer_ip" placeholder="IP externe" />
        </label>
        <label class="field">
          <span>Port</span>
          <input class="input" type="number" [(ngModel)]="filters.port" />
        </label>
        <label class="field">
          <span>Service</span>
          <input class="input" [(ngModel)]="filters.service" placeholder="ssh, https..." />
        </label>
        <label class="field">
          <span>Durée min. (s)</span>
          <input class="input" type="number" [(ngModel)]="filters.min_duration" />
        </label>
        <label class="field">
          <span>Volume min.</span>
          <input class="input" type="number" [(ngModel)]="filters.min_total_bytes" />
        </label>
        <label class="field">
          <span>Verdict peer</span>
          <select class="select" [(ngModel)]="filters.peer_verdict">
            <option value="">Tous</option>
            <option value="malicious">Malveillant</option>
            <option value="suspicious">Suspect</option>
            <option value="clean">Propre</option>
            <option value="unknown">Inconnu</option>
          </select>
        </label>
        <label class="field">
          <span>Tri</span>
          <select class="select" [(ngModel)]="filters.ordering">
            <option value="-started_at">Date récente</option>
            <option value="started_at">Date ancienne</option>
            <option value="-duration_seconds">Durée</option>
            <option value="-total_bytes">Poids trafic</option>
          </select>
        </label>
        <button class="btn" (click)="load()">Filtrer</button>
      </section>

      <section class="card">
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Date</th>
                <th>Durée</th>
                <th>Source</th>
                <th>Destination</th>
                <th>Service</th>
                <th>Application</th>
                <th>Direction</th>
                <th>Trafic</th>
                <th>Paquets</th>
              </tr>
            </thead>
            <tbody>
              @for (flow of flows(); track flow.id) {
                <tr>
                  <td>{{ flow.started_at | date:'medium' }}</td>
                  <td>{{ duration(flow.duration_seconds) }}</td>
                  <td>{{ flow.src_ip }}:{{ flow.src_port || '-' }}</td>
                  <td>{{ flow.dst_ip }}:{{ flow.dst_port || '-' }}</td>
                  <td>{{ flow.protocol }} / {{ flow.service || '-' }}</td>
                  <td>{{ flow.application || '-' }}</td>
                  <td><span class="badge info">{{ flow.direction }}</span></td>
                  <td>{{ bytes(flow.total_bytes) }}</td>
                  <td>{{ flow.total_packets || 0 }}</td>
                </tr>
              } @empty {
                <tr><td colspan="9"><div class="empty">Aucun flow.</div></td></tr>
              }
            </tbody>
          </table>
        </div>
      </section>
    </div>
  `,
})
export class FlowsPageComponent implements OnInit {
  private readonly api = inject(ApiService);
  readonly flows = signal<Flow[]>([]);
  readonly structures = signal<Structure[]>([]);
  readonly bytes = formatBytes;
  readonly duration = formatDuration;
  filters: FlowFilters = {
    structure_id: null,
    ordering: '-started_at',
    date_from: '',
    date_to: '',
    ip: '',
    peer_ip: '',
    port: null,
    service: '',
    min_duration: null,
    min_total_bytes: null,
    peer_verdict: '',
  };

  ngOnInit() {
    this.api.structures().subscribe((data) => this.structures.set(data.results));
    this.load();
  }

  load() {
    this.api.flows(this.normalizedFilters()).subscribe((data) => this.flows.set(data.results));
  }

  exportUrl() {
    return this.api.exportFlowsUrl(this.normalizedFilters());
  }

  private normalizedFilters(): QueryParams {
    const result: QueryParams = { ...this.filters };
    if (result['date_from']) result['date_from'] = `${result['date_from']}:00`;
    if (result['date_to']) result['date_to'] = `${result['date_to']}:00`;
    return result;
  }
}
