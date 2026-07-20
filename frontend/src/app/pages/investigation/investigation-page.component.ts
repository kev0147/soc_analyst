import { DatePipe } from '@angular/common';
import { Component, OnInit, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import { ApiService, QueryParams } from '../../core/api/api.service';
import { FlowImport, PeerInvestigationObservation, Structure, TopPeer } from '../../core/api/api.types';
import { formatBytes, formatDuration } from '../../shared/formatters';

@Component({
  selector: 'app-investigation-page',
  standalone: true,
  imports: [DatePipe, FormsModule],
  template: `
    <div class="page">
      <div class="page-title">
        <div>
          <h1>Investigation</h1>
          <p>Une ligne par IP externe, avec toutes les communications hôte/port associées.</p>
        </div>
        <button class="btn" (click)="createBulletin()" [disabled]="selectedObservationIds().length === 0">
          Créer un bulletin ({{ selectedObservationIds().length }})
        </button>
      </div>

      <section class="card filters">
        <label class="field">
          <span>Structure</span>
          <select class="select" [(ngModel)]="structureId" (ngModelChange)="filterImports()">
            @for (structure of structures(); track structure.id) {
              <option [ngValue]="structure.id">{{ structure.code }} — {{ structure.name }}</option>
            }
          </select>
        </label>
        <label class="field">
          <span>Import</span>
          <select class="select" [(ngModel)]="importId">
            <option [ngValue]="0">Tous les imports de la structure</option>
            @for (item of visibleImports(); track item.id) {
              <option [ngValue]="item.id">#{{ item.id }} — {{ item.original_filename }}</option>
            }
          </select>
        </label>
        <label class="field">
          <span>Début</span>
          <input class="input" type="datetime-local" [(ngModel)]="dateFrom" />
        </label>
        <label class="field">
          <span>Fin</span>
          <input class="input" type="datetime-local" [(ngModel)]="dateTo" />
        </label>
        <label class="field">
          <span>Adresse IP peer</span>
          <input class="input" [(ngModel)]="peerIp" placeholder="IP exacte" (keyup.enter)="load()" />
        </label>
        <label class="field">
          <span>Verdict</span>
          <select class="select" [(ngModel)]="verdict">
            <option value="">Tous</option>
            <option value="malicious">Malveillant</option>
            <option value="suspicious">Suspect</option>
            <option value="unknown">Inconnu</option>
            <option value="clean">Propre</option>
          </select>
        </label>
        <label class="field">
          <span>Pays</span>
          <input class="input" [(ngModel)]="country" placeholder="BF, FR..." />
        </label>
        <label class="field">
          <span>Port hôte</span>
          <input class="input" type="number" [(ngModel)]="hostPort" />
        </label>
        <label class="field">
          <span>Service</span>
          <input class="input" [(ngModel)]="service" placeholder="ssh, https..." />
        </label>
        <label class="field">
          <span>Durée minimale (s)</span>
          <input class="input" type="number" [(ngModel)]="minDuration" />
        </label>
        <label class="field">
          <span>Volume minimal (octets)</span>
          <input class="input" type="number" [(ngModel)]="minBytes" />
        </label>
        <label class="field">
          <span>Classement</span>
          <select class="select" [(ngModel)]="sort">
            <option value="verdict">Verdict de l’analyse</option>
            <option value="total_duration_seconds">Durée totale</option>
            <option value="total_bytes">Volume total</option>
            <option value="flow_count">Nombre de flows</option>
            <option value="score">Score de réputation</option>
            <option value="last_seen_at">Dernière activité</option>
          </select>
        </label>
        <button class="btn secondary" (click)="load()">Rechercher</button>
      </section>

      @if (message()) {
        <p class="muted">{{ message() }}</p>
      }

      <section class="peer-list">
        @for (peer of peers(); track peer.peer_ip) {
          <article class="card peer-card">
            <div class="peer-summary">
              <div>
                <strong class="peer-ip">{{ peer.peer_ip }}</strong>
                <span>{{ peer.country || 'Pays inconnu' }}</span>
              </div>
              <div>
                <span class="badge" [class.danger]="peer.verdict === 'malicious'" [class.warning]="peer.verdict === 'suspicious'" [class.success]="peer.verdict === 'clean'">
                  {{ peer.verdict }} · score {{ peer.score ?? '-' }}
                </span>
                <small class="muted">{{ peer.successful_source_count }}/{{ peer.source_count }} source(s) réussie(s)</small>
              </div>
              <div><small class="muted">Hôtes</small><strong>{{ peer.host_count }}</strong></div>
              <div><small class="muted">Flows</small><strong>{{ peer.flow_count }}</strong></div>
              <div><small class="muted">Volume</small><strong>{{ bytes(peer.total_bytes) }}</strong></div>
              <div><small class="muted">Durée totale</small><strong>{{ duration(peer.total_duration_seconds) }}</strong></div>
              <button
                class="btn secondary"
                (click)="togglePeer(peer)"
                [title]="observationIds(peer).length ? '' : 'Les communications doivent être synchronisées après l’import ou l’analyse IP.'"
              >
                {{ peerSelected(peer) ? 'Retirer les communications' : 'Sélectionner les communications' }}
              </button>
            </div>

            <div class="peer-metrics">
              <span><small>Paquets</small><strong>{{ peer.total_packets }}</strong></span>
              <span><small>Durée moyenne</small><strong>{{ duration(peer.avg_duration_seconds) }}</strong></span>
              <span><small>Durée maximale</small><strong>{{ duration(peer.max_duration_seconds) }}</strong></span>
              <span><small>Première activité</small><strong>{{ peer.first_seen ? (peer.first_seen | date:'medium') : '-' }}</strong></span>
              <span><small>Dernière activité</small><strong>{{ peer.last_seen ? (peer.last_seen | date:'medium') : '-' }}</strong></span>
            </div>

            <div class="reputation-details">
              <strong>Réputation</strong>
              @for (result of peer.reputation_results; track result.source) {
                <span>
                  {{ result.source }} : {{ result.status }} · {{ result.verdict }} · score {{ result.score ?? '-' }}
                  @if (result.country) { · {{ result.country }} }
                </span>
              } @empty {
                <span class="muted">Aucun résultat détaillé de réputation.</span>
              }
            </div>

            <details>
              <summary>Voir {{ peer.observations.length }} communication(s) hôte/port</summary>
              <div class="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th></th>
                      <th>Hôte</th>
                      <th>Port/service</th>
                      <th>Catégorie</th>
                      <th>Flows</th>
                      <th>Paquets</th>
                      <th>Volume</th>
                      <th>Durée</th>
                      <th>Première activité</th>
                      <th>Dernière activité</th>
                    </tr>
                  </thead>
                  <tbody>
                    @for (observation of peer.observations; track observation.id) {
                      <tr>
                        <td><input type="checkbox" [checked]="isSelected(observation.id)" (change)="toggleObservation(observation)" /></td>
                        <td>{{ observation.host_ip || '-' }}</td>
                        <td>{{ observation.host_port ?? '-' }} / {{ observation.host_service || '-' }}</td>
                        <td>{{ observation.host_port_category || '-' }}</td>
                        <td>{{ observation.flow_count }}</td>
                        <td>{{ observation.total_packets }}</td>
                        <td>{{ bytes(observation.total_bytes) }}</td>
                        <td>{{ duration(observation.total_duration_seconds) }}</td>
                        <td>{{ observation.first_seen_at ? (observation.first_seen_at | date:'medium') : '-' }}</td>
                        <td>{{ observation.last_seen_at ? (observation.last_seen_at | date:'medium') : '-' }}</td>
                      </tr>
                    } @empty {
                      <tr><td colspan="10"><div class="empty">Aucune observation synchronisée. Lance une analyse IP pour cette peer.</div></td></tr>
                    }
                  </tbody>
                </table>
              </div>
            </details>
          </article>
        } @empty {
          <div class="card empty">Aucune peer pour ces filtres.</div>
        }
      </section>
    </div>
  `,
  styles: `
    .peer-list { display: grid; gap: 14px; }
    .peer-card { display: grid; gap: 16px; }
    .peer-summary {
      display: grid;
      grid-template-columns: minmax(180px, 1.5fr) repeat(5, minmax(90px, auto)) auto;
      gap: 14px;
      align-items: center;
    }
    .peer-summary > div { display: grid; gap: 4px; }
    .peer-metrics { display: grid; grid-template-columns: repeat(5, minmax(130px, 1fr)); gap: 10px; }
    .peer-metrics span { display: grid; gap: 4px; padding: 10px; border: 1px solid var(--border); border-radius: 8px; }
    .peer-metrics small { color: var(--muted); }
    .reputation-details { display: flex; flex-wrap: wrap; gap: 10px 18px; align-items: center; }
    .peer-ip { font-size: 18px; }
    summary { cursor: pointer; color: var(--muted); }
    @media (max-width: 1100px) {
      .peer-summary { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .peer-metrics { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    }
  `,
})
export class InvestigationPageComponent implements OnInit {
  private readonly api = inject(ApiService);
  private readonly router = inject(Router);
  readonly structures = signal<Structure[]>([]);
  readonly imports = signal<FlowImport[]>([]);
  readonly visibleImports = signal<FlowImport[]>([]);
  readonly peers = signal<TopPeer[]>([]);
  readonly selectedObservationIds = signal<number[]>([]);
  readonly message = signal('');
  readonly bytes = formatBytes;
  readonly duration = formatDuration;

  structureId = 0;
  importId = 0;
  dateFrom = '';
  dateTo = '';
  peerIp = '';
  verdict = '';
  country = '';
  hostPort: number | null = null;
  service = '';
  minDuration: number | null = null;
  minBytes: number | null = null;
  sort = 'verdict';

  ngOnInit() {
    this.api.imports().subscribe((data) => {
      this.imports.set(data.results);
      this.filterImports();
    });
    this.api.structures({ is_active: true }).subscribe((data) => {
      this.structures.set(data.results);
      this.structureId = data.results[0]?.id || 0;
      this.filterImports();
      if (this.structureId) this.load();
    });
  }

  filterImports() {
    this.visibleImports.set(this.imports().filter((item) => item.structure === this.structureId));
    if (!this.visibleImports().some((item) => item.id === this.importId)) this.importId = 0;
  }

  load() {
    if (!this.structureId) return;
    const params: QueryParams = {
      structure_id: this.structureId,
      import_id: this.importId || null,
      date_from: this.normalizedDate(this.dateFrom),
      date_to: this.normalizedDate(this.dateTo),
      peer_ip: this.peerIp,
      verdict: this.verdict,
      country: this.country,
      host_port: this.hostPort,
      service: this.service,
      min_duration: this.minDuration,
      min_total_bytes: this.minBytes,
      sort: this.sort,
      limit: 25,
    };
    this.message.set('Recherche en cours...');
    this.selectedObservationIds.set([]);
    this.api.topPeers(params).subscribe({
      next: (data) => {
        this.peers.set(data.results);
        this.message.set(`${data.results.length} peer(s) trouvée(s).`);
      },
      error: () => this.message.set('Recherche impossible.'),
    });
  }

  toggleObservation(observation: PeerInvestigationObservation) {
    const selected = new Set(this.selectedObservationIds());
    selected.has(observation.id) ? selected.delete(observation.id) : selected.add(observation.id);
    this.selectedObservationIds.set([...selected]);
  }

  togglePeer(peer: TopPeer) {
    const peerObservationIds = this.observationIds(peer);
    if (peerObservationIds.length === 0) {
      this.message.set(`Aucune communication sélectionnable pour ${peer.peer_ip}. Relance l’analyse IP pour synchroniser les anciens imports.`);
      return;
    }
    const selected = new Set(this.selectedObservationIds());
    const allSelected = peerObservationIds.every((id) => selected.has(id));
    for (const id of peerObservationIds) allSelected ? selected.delete(id) : selected.add(id);
    this.selectedObservationIds.set([...selected]);
  }

  peerSelected(peer: TopPeer): boolean {
    const ids = this.observationIds(peer);
    const selected = new Set(this.selectedObservationIds());
    return ids.length > 0 && ids.every((id) => selected.has(id));
  }

  observationIds(peer: TopPeer): number[] {
    return peer.observations?.map((item) => item.id) || peer.observation_ids || [];
  }

  isSelected(id: number): boolean {
    return this.selectedObservationIds().includes(id);
  }

  createBulletin() {
    this.router.navigate(['/bulletins/new'], {
      queryParams: {
        observations: this.selectedObservationIds().join(','),
        structure: this.structureId,
      },
    });
  }

  private normalizedDate(value: string): string {
    return value && value.length === 16 ? `${value}:00` : value;
  }
}
