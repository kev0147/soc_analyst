import { DatePipe } from '@angular/common';
import { Component, OnInit, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import { ApiService } from '../../core/api/api.service';
import { PeerObservation, Structure, TopPeer } from '../../core/api/api.types';
import { formatBytes, formatDuration } from '../../shared/formatters';

interface SocPeerFilters {
  peer_ip: string;
  structure_id: number | null;
  date_from: string;
  date_to: string;
  verdict: string;
  host_port: number | null;
  service: string;
  min_duration: number | null;
  sort: string;
  suspicious_only: boolean;
  limit: number;
}

@Component({
  selector: 'app-soc-peers-page',
  standalone: true,
  imports: [DatePipe, FormsModule],
  template: `
    <div class="page">
      <div class="page-title">
        <div>
          <h1>Peers observées</h1>
          <p>Rechercher une IP externe observée, consulter ses communications et la sélectionner pour un bulletin.</p>
        </div>
        <button class="btn" (click)="goCreate()" [disabled]="selectedObservationIds.size === 0">
          Créer bulletin ({{ selectedObservationIds.size }})
        </button>
      </div>

      <section class="card filters">
        <label class="field">
          <span>Adresse IP peer</span>
          <input
            class="input"
            [(ngModel)]="filters.peer_ip"
            placeholder="IP exacte, ex. 203.0.113.10"
            (keyup.enter)="load()"
          />
        </label>
        <label class="field">
          <span>Structure</span>
          <select class="select" [(ngModel)]="filters.structure_id">
            <option [ngValue]="null">Toutes les structures</option>
            @for (structure of structures(); track structure.id) {
              <option [ngValue]="structure.id">{{ structure.code }} — {{ structure.name }}</option>
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
          <span>Verdict</span>
          <select class="select" [(ngModel)]="filters.verdict">
            <option value="">Tous</option>
            <option value="malicious">Malveillant</option>
            <option value="suspicious">Suspect</option>
            <option value="clean">Propre</option>
            <option value="unknown">Inconnu</option>
          </select>
        </label>
        <label class="field">
          <span>Port host</span>
          <input class="input" type="number" [(ngModel)]="filters.host_port" />
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
          <span>Tri top peers</span>
          <select class="select" [(ngModel)]="filters.sort">
            <option value="total_duration_seconds">Durée totale</option>
            <option value="total_bytes">Volume</option>
            <option value="flow_count">Nombre de flows</option>
            <option value="score">Score réputation</option>
            <option value="last_seen_at">Dernière activité</option>
          </select>
        </label>
        <button class="btn secondary" (click)="load()">Rechercher</button>
      </section>

      <section class="card">
        <h2>Communications agrégées par peer</h2>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Peer IP</th>
                <th>Pays</th>
                <th>Verdict</th>
                <th>Score</th>
                <th>Hosts</th>
                <th>Ports</th>
                <th>Services</th>
                <th>Flows</th>
                <th>Durée</th>
                <th>Volume</th>
                <th>Dernière activité</th>
              </tr>
            </thead>
            <tbody>
              @for (peer of topPeers(); track peer.peer_ip) {
                <tr>
                  <td>{{ peer.peer_ip }}</td>
                  <td>{{ peer.country || '-' }}</td>
                  <td><span class="badge" [class.danger]="peer.verdict === 'malicious'" [class.warning]="peer.verdict === 'suspicious'" [class.success]="peer.verdict === 'clean'">{{ peer.verdict }}</span></td>
                  <td>{{ peer.score ?? '-' }}</td>
                  <td>{{ peer.host_ips.join(', ') || '-' }}</td>
                  <td>{{ peer.host_ports.join(', ') || '-' }}</td>
                  <td>{{ peer.services.join(', ') || '-' }}</td>
                  <td>{{ peer.flow_count }}</td>
                  <td>{{ duration(peer.total_duration_seconds) }}</td>
                  <td>{{ bytes(peer.total_bytes) }}</td>
                  <td>{{ peer.last_seen ? (peer.last_seen | date:'medium') : '-' }}</td>
                </tr>
              } @empty {
                <tr><td colspan="11"><div class="empty">Aucun peer pour ces filtres.</div></td></tr>
              }
            </tbody>
          </table>
        </div>
      </section>

      <section class="card">
        <h2>Observations sélectionnables pour un bulletin</h2>
        <p class="muted">Chaque ligne correspond à une communication peer → hôte/port. Sélectionne les lignes utiles avant de créer le bulletin.</p>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th></th>
                <th>Peer</th>
                <th>Host</th>
                <th>Port/service</th>
                <th>Verdict</th>
                <th>Score</th>
                <th>Flows</th>
                <th>Durée</th>
                <th>Volume</th>
                <th>Dernière activité</th>
              </tr>
            </thead>
            <tbody>
              @for (item of suggestions(); track item.id) {
                <tr>
                  <td><input type="checkbox" [checked]="selectedObservationIds.has(item.id)" (change)="toggleObservation(item.id)" /></td>
                  <td>{{ item.peer_ip }} <span class="muted">{{ item.peer_country || '' }}</span></td>
                  <td>{{ item.host_ip || '-' }}</td>
                  <td>{{ item.host_port || '-' }} / {{ item.host_service || '-' }}</td>
                  <td><span class="badge" [class.danger]="item.reputation_verdict === 'malicious'" [class.warning]="item.reputation_verdict === 'suspicious'" [class.success]="item.reputation_verdict === 'clean'">{{ item.reputation_verdict }}</span></td>
                  <td>{{ item.reputation_score ?? '-' }}</td>
                  <td>{{ item.flow_count }}</td>
                  <td>{{ duration(item.total_duration_seconds) }}</td>
                  <td>{{ bytes(item.total_bytes) }}</td>
                  <td>{{ item.last_seen_at ? (item.last_seen_at | date:'medium') : '-' }}</td>
                </tr>
              } @empty {
                <tr><td colspan="10"><div class="empty">Aucune suggestion.</div></td></tr>
              }
            </tbody>
          </table>
        </div>
      </section>
    </div>
  `,
})
export class SocPeersPageComponent implements OnInit {
  private readonly api = inject(ApiService);
  private readonly router = inject(Router);
  readonly topPeers = signal<TopPeer[]>([]);
  readonly suggestions = signal<PeerObservation[]>([]);
  readonly structures = signal<Structure[]>([]);
  readonly bytes = formatBytes;
  readonly duration = formatDuration;
  readonly selectedObservationIds = new Set<number>();

  filters: SocPeerFilters = {
    peer_ip: '',
    structure_id: null,
    date_from: '',
    date_to: '',
    verdict: '',
    host_port: null,
    service: '',
    min_duration: null,
    sort: 'total_duration_seconds',
    suspicious_only: false,
    limit: 25,
  };

  ngOnInit() {
    this.api.structures({ is_active: true }).subscribe((data) => this.structures.set(data.results));
    this.load();
  }

  load() {
    const params = this.normalizedFilters();
    this.api.topPeers(params).subscribe((data) => this.topPeers.set(data.results));
    this.api.peerObservationSuggestions(params).subscribe((data) => this.suggestions.set(data.results));
  }

  toggleObservation(id: number) {
    this.selectedObservationIds.has(id) ? this.selectedObservationIds.delete(id) : this.selectedObservationIds.add(id);
  }

  goCreate() {
    const ids = [...this.selectedObservationIds].join(',');
    this.router.navigate(['/bulletins/new'], { queryParams: { observations: ids } });
  }

  private normalizedFilters() {
    const result: Record<string, string | number | boolean | null> = { ...this.filters };
    if (result['date_from']) result['date_from'] = `${result['date_from']}:00`;
    if (result['date_to']) result['date_to'] = `${result['date_to']}:00`;
    return result;
  }
}
