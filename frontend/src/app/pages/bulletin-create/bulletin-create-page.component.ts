import { DatePipe } from '@angular/common';
import { Component, OnInit, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { ApiService } from '../../core/api/api.service';
import { CatalogItem, Network, PeerObservation, RiskProfile, Structure } from '../../core/api/api.types';
import { formatBytes, formatDuration } from '../../shared/formatters';

@Component({
  selector: 'app-bulletin-create-page',
  standalone: true,
  imports: [DatePipe, FormsModule, RouterLink],
  template: `
    <div class="page">
      <div class="page-title">
        <div>
          <h1>Créer un bulletin</h1>
          <p>Un peer peut concerner plusieurs hôtes et ports. Sélectionne les communications à documenter.</p>
        </div>
        <a class="btn secondary" routerLink="/investigation">Choisir des peers</a>
      </div>

      <section class="card">
        <h2>Informations bulletin</h2>
        <div class="grid cols-3">
          <label class="field">
            <span>Structure</span>
            <select class="select" [(ngModel)]="structureId">
              @for (structure of structures(); track structure.id) {
                <option [ngValue]="structure.id">{{ structure.code }} — {{ structure.name }}</option>
              }
            </select>
          </label>
          <label class="field">
            <span>Référence externe</span>
            <input class="input" [(ngModel)]="externalReference" placeholder="Ancienne ref_alerte si besoin" />
          </label>
          <label class="field">
            <span>Gravité</span>
            <select class="select" [(ngModel)]="severity">
              <option value="">Automatique depuis les risques</option>
              <option value="low">Faible</option>
              <option value="medium">Moyenne</option>
              <option value="high">Élevée</option>
              <option value="critical">Critique</option>
            </select>
          </label>
          <label class="field">
            <span>Status</span>
            <select class="select" [(ngModel)]="status">
              <option value="draft">Brouillon</option>
              <option value="sent">Envoyé</option>
            </select>
          </label>
        </div>
      </section>

      <section class="card">
        <h2>Observations sélectionnées</h2>
        <div class="toolbar">
          <input class="input" [(ngModel)]="observationSearch" placeholder="Filtrer peer IP, ex: 203.0.113.10" />
          <button class="btn secondary" (click)="loadObservations()">Rechercher</button>
        </div>
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
                <th>Durée</th>
                <th>Volume</th>
                <th>Dernière activité</th>
              </tr>
            </thead>
            <tbody>
              @for (item of observations(); track item.id) {
                <tr>
                  <td><input type="checkbox" [checked]="selectedObservationIds().includes(item.id)" (change)="toggleObservation(item)" /></td>
                  <td>{{ item.peer_ip }} <span class="muted">{{ item.peer_country || '' }}</span></td>
                  <td>{{ item.host_ip || '-' }}</td>
                  <td>{{ item.host_port || '-' }} / {{ item.host_service || '-' }}</td>
                  <td><span class="badge" [class.danger]="item.reputation_verdict === 'malicious'" [class.warning]="item.reputation_verdict === 'suspicious'" [class.success]="item.reputation_verdict === 'clean'">{{ item.reputation_verdict }}</span></td>
                  <td>{{ item.reputation_score ?? '-' }}</td>
                  <td>{{ duration(item.total_duration_seconds) }}</td>
                  <td>{{ bytes(item.total_bytes) }}</td>
                  <td>{{ item.last_seen_at ? (item.last_seen_at | date:'medium') : '-' }}</td>
                </tr>
              } @empty {
                <tr><td colspan="9"><div class="empty">Aucune observation. Utilise la page Investigation ou lance une recherche.</div></td></tr>
              }
            </tbody>
          </table>
        </div>
      </section>

      <section class="card">
        <h2>Activités concernées</h2>
        <p class="muted">Un bulletin peut contenir plusieurs activités. Elles déterminent les risques proposés.</p>
        <div class="toolbar">
          @for (activity of activities(); track activity.id) {
            <label><input type="checkbox" [checked]="selectedActivityIds().includes(activity.id)" (change)="toggleActivity(activity.id)" /> {{ activity.name }}</label>
          }
        </div>
      </section>

      <section class="card">
        <h2>Risques compatibles</h2>
        <p class="muted">Seuls les risques correspondant aux activités choisies et aux ports hôtes sélectionnés sont affichés.</p>
        <div class="grid cols-2">
          @for (risk of visibleRiskProfiles(); track risk.id) {
            <label class="risk-card">
              <input type="checkbox" [checked]="selectedRiskIds().includes(risk.id)" (change)="toggleRisk(risk.id)" />
              <strong>{{ risk.name }}</strong>
              <small>Activité : {{ risk.activity_name }}</small>
              <span class="badge warning">{{ risk.default_severity }}</span>
              <small>Impact : {{ risk.impact }}</small>
              <small>Recommandation : {{ risk.recommendation }}</small>
            </label>
          } @empty {
            <p class="muted">Aucun risque compatible avec les activités et ports sélectionnés.</p>
          }
        </div>
      </section>

      <section class="card toolbar">
        <label><input type="checkbox" [(ngModel)]="forceDuplicate" /> Forcer si doublon</label>
        <button class="btn" (click)="create()" [disabled]="!canCreate()">Créer le bulletin</button>
        @if (message()) {
          <p class="muted">{{ message() }}</p>
        }
      </section>
    </div>
  `,
  styles: `
    .risk-card {
      display: grid;
      gap: 8px;
      padding: 14px;
      border: 1px solid var(--line);
      border-radius: 14px;
      background: rgba(255, 255, 255, 0.03);
    }
    .risk-card small {
      color: var(--muted);
      line-height: 1.4;
    }
  `,
})
export class BulletinCreatePageComponent implements OnInit {
  private readonly api = inject(ApiService);
  private readonly router = inject(Router);
  private readonly route = inject(ActivatedRoute);
  readonly networks = signal<Network[]>([]);
  readonly structures = signal<Structure[]>([]);
  readonly observations = signal<PeerObservation[]>([]);
  readonly activities = signal<CatalogItem[]>([]);
  readonly riskProfiles = signal<RiskProfile[]>([]);
  readonly selectedActivityIds = signal<number[]>([]);
  readonly selectedObservationIds = signal<number[]>([]);
  readonly selectedRiskIds = signal<number[]>([]);
  readonly message = signal('');
  readonly bytes = formatBytes;
  readonly duration = formatDuration;

  structureId = 0;
  externalReference = '';
  severity = '';
  status = 'draft';
  forceDuplicate = false;
  observationSearch = '';

  ngOnInit() {
    const queryParams = this.route.snapshot.queryParamMap;
    const ids = queryParams.get('observations');
    if (ids) {
      this.selectedObservationIds.set(ids.split(',').map((value) => Number(value)).filter(Boolean));
    }
    const peer = queryParams.get('peer');
    if (peer) this.observationSearch = peer;
    const structureId = Number(queryParams.get('structure'));
    if (structureId) this.structureId = structureId;
    this.api.networks().subscribe((data) => {
      this.networks.set(data.results);
      this.syncStructureFromObservations();
    });
    this.api.structures({ is_active: true }).subscribe((data) => {
      this.structures.set(data.results);
      if (data.results.length && !this.structureId) this.structureId = data.results[0].id;
    });
    this.api.riskProfiles({ is_active: true }).subscribe((data) => this.riskProfiles.set(data.results));
    this.api.activities({ is_active: true }).subscribe((data) => this.activities.set(data.results));
    this.loadObservations();
  }

  loadObservations() {
    this.api.peerObservationSuggestions({
      ids: this.selectedObservationIds().length ? this.selectedObservationIds().join(',') : null,
      peer_ip: this.observationSearch,
      structure_id: this.structureId || null,
      limit: 50,
    }).subscribe((data) => {
      this.observations.set(data.results);
      this.syncStructureFromObservations();
    });
  }

  toggleObservation(item: PeerObservation) {
    const selected = new Set(this.selectedObservationIds());
    selected.has(item.id) ? selected.delete(item.id) : selected.add(item.id);
    this.selectedObservationIds.set([...selected]);
    this.syncStructureFromNetworkId(item.network);
  }

  toggleRisk(id: number) {
    const selected = new Set(this.selectedRiskIds());
    selected.has(id) ? selected.delete(id) : selected.add(id);
    this.selectedRiskIds.set([...selected]);
  }

  canCreate() {
    return this.structureId && this.selectedObservationIds().length > 0 && this.selectedActivityIds().length > 0 && this.selectedRiskIds().length > 0;
  }

  create() {
    const payload: Record<string, unknown> = {
      structure_id: this.structureId,
      external_reference: this.externalReference,
      status: this.status,
      peer_observation_ids: this.selectedObservationIds(),
      risk_profile_ids: this.selectedRiskIds(),
      force_duplicate: this.forceDuplicate,
    };
    if (this.severity) {
      payload['severity'] = this.severity;
    }
    this.api.createBulletinFromFindings(payload).subscribe({
      next: () => this.router.navigateByUrl('/bulletins'),
      error: (error) => {
        if (error.status === 409) {
          this.message.set('Doublon détecté. Coche “Forcer si doublon” si tu veux créer quand même.');
        } else {
          this.message.set('Création impossible. Vérifie structure, observations et risques.');
        }
      },
    });
  }

  private syncStructureFromNetworkId(networkId: number) {
    const network = this.networks().find((item) => item.id === networkId);
    if (network) {
      this.structureId = network.structure;
    }
  }

  toggleActivity(id: number) {
    const selected = new Set(this.selectedActivityIds());
    selected.has(id) ? selected.delete(id) : selected.add(id);
    this.selectedActivityIds.set([...selected]);
    const visible = new Set(this.visibleRiskProfiles().map((risk) => risk.id));
    this.selectedRiskIds.set(this.selectedRiskIds().filter((riskId) => visible.has(riskId)));
  }

  visibleRiskProfiles() {
    const activities = new Set(this.selectedActivityIds());
    const selectedObservations = this.observations().filter((item) => this.selectedObservationIds().includes(item.id));
    const ports = new Set(selectedObservations.map((item) => item.host_port).filter((port): port is number => port !== null));
    return this.riskProfiles().filter((risk) =>
      activities.has(risk.activity) &&
      (risk.port_services.length === 0 || risk.port_services.some((item) => ports.has(item.port)))
    );
  }

  private syncStructureFromObservations() {
    const selectedId = this.selectedObservationIds()[0];
    const observation = this.observations().find((item) => item.id === selectedId);
    if (observation) this.syncStructureFromNetworkId(observation.network);
  }
}
