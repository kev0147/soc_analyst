import { DatePipe } from '@angular/common';
import { Component, OnInit, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { ApiService } from '../../core/api/api.service';
import { Network, PeerObservation, RiskProfile, Structure } from '../../core/api/api.types';
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
          <button class="btn secondary" (click)="searchObservations()">Rechercher et ajouter</button>
        </div>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th></th>
                <th>Peer</th>
                <th>Structure/réseau</th>
                <th>Host</th>
                <th>Port/service</th>
                <th>Catégorie</th>
                <th>Verdict</th>
                <th>Flows/paquets</th>
                <th>Durées</th>
                <th>Volume</th>
                <th>Période</th>
              </tr>
            </thead>
            <tbody>
              @for (item of observations(); track item.id) {
                <tr>
                  <td><input type="checkbox" [checked]="selectedObservationIds().includes(item.id)" (change)="toggleObservation(item)" /></td>
                  <td>
                    <strong>{{ item.peer_ip }}</strong><br><span class="muted">{{ item.peer_country || 'Pays inconnu' }}</span>
                    <details><summary>Réputation par plateforme</summary>
                      @for (result of item.reputation_results; track result.source) {
                        <small>{{ result.source }} : {{ result.verdict }} · {{ result.score ?? '-' }} · {{ result.country || '-' }}</small>
                      } @empty { <small>Aucun résultat détaillé.</small> }
                    </details>
                  </td>
                  <td>{{ item.structure_code }}<br><span class="muted">{{ item.network_name }}</span></td>
                  <td>{{ item.host_ip || '-' }}</td>
                  <td>{{ item.host_port || '-' }} / {{ item.host_service || '-' }}</td>
                  <td>{{ item.host_port_category || '-' }}</td>
                  <td><span class="badge" [class.danger]="item.reputation_verdict === 'malicious'" [class.warning]="item.reputation_verdict === 'suspicious'" [class.success]="item.reputation_verdict === 'clean'">{{ item.reputation_verdict }}</span></td>
                  <td>{{ item.flow_count }} / {{ item.total_packets }}</td>
                  <td>Total : {{ duration(item.total_duration_seconds) }}<br><span class="muted">Max : {{ duration(item.max_duration_seconds || 0) }} · Moy : {{ duration(item.avg_duration_seconds || 0) }}</span></td>
                  <td>{{ bytes(item.total_bytes) }}</td>
                  <td>{{ item.first_seen_at ? (item.first_seen_at | date:'short') : '-' }}<br>{{ item.last_seen_at ? (item.last_seen_at | date:'short') : '-' }}</td>
                </tr>
              } @empty {
                <tr><td colspan="11"><div class="empty">Aucune communication sélectionnée. Choisis une ou plusieurs communications dans <a routerLink="/investigation">Investigation</a>, ou recherche une peer IP ci-dessus.</div></td></tr>
              }
            </tbody>
          </table>
        </div>
      </section>

      <section class="card">
        <h2>Risques compatibles</h2>
        <p class="muted">Les risques sont proposés selon les ports hôtes sélectionnés. Les activités correspondantes seront ajoutées automatiquement au bulletin.</p>
        @if (uncoveredObservations().length) {
          <p class="badge warning">{{ uncoveredObservations().length }} communication(s) n’ont pas encore de risque compatible sélectionné.</p>
        }
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
    td details small { display: block; color: var(--muted); margin-top: 4px; white-space: nowrap; }
  `,
})
export class BulletinCreatePageComponent implements OnInit {
  private readonly api = inject(ApiService);
  private readonly router = inject(Router);
  private readonly route = inject(ActivatedRoute);
  readonly networks = signal<Network[]>([]);
  readonly structures = signal<Structure[]>([]);
  readonly observations = signal<PeerObservation[]>([]);
  readonly riskProfiles = signal<RiskProfile[]>([]);
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
    this.loadObservations();
  }

  loadObservations(selectedOnly = true) {
    this.api.peerObservationSuggestions({
      ids: selectedOnly && this.selectedObservationIds().length ? this.selectedObservationIds().join(',') : null,
      peer_ip: selectedOnly ? null : this.observationSearch,
      structure_id: selectedOnly && this.selectedObservationIds().length ? null : (this.structureId || null),
      limit: 50,
    }).subscribe({
      next: (data) => {
        const merged = selectedOnly
          ? data.results
          : [...this.observations(), ...data.results].filter((item, index, items) => items.findIndex((other) => other.id === item.id) === index);
        this.observations.set(merged);
        if (!selectedOnly) {
          this.selectedObservationIds.set([...new Set([...this.selectedObservationIds(), ...data.results.map((item) => item.id)])]);
        }
        this.syncStructureFromObservations();
        if (selectedOnly && this.selectedObservationIds().length && data.results.length === 0) {
          this.message.set('Les observations sélectionnées ne sont plus disponibles. Resynchronise les observations depuis Analyse IP, puis retourne dans Investigation.');
        } else {
          this.message.set(selectedOnly ? `${data.results.length} observation(s) sélectionnée(s) chargée(s).` : `${data.results.length} résultat(s) ajouté(s) et sélectionné(s).`);
        }
      },
      error: (error) => this.message.set(this.errorMessage(error, 'Impossible de charger les observations.')),
    });
  }

  searchObservations() {
    if (!this.observationSearch.trim()) {
      this.message.set('Saisis une adresse IP peer à rechercher.');
      return;
    }
    this.loadObservations(false);
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
    return this.structureId && this.selectedObservationIds().length > 0 && this.selectedRiskIds().length > 0 && this.uncoveredObservations().length === 0;
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
          this.message.set(this.errorMessage(error, 'Création impossible. Vérifie structure, observations et risques.'));
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

  visibleRiskProfiles() {
    const selectedObservations = this.observations().filter((item) => this.selectedObservationIds().includes(item.id));
    const ports = new Set(selectedObservations.map((item) => item.host_port).filter((port): port is number => port !== null));
    return this.riskProfiles().filter((risk) =>
      risk.port_services.length === 0 || risk.port_services.some((item) => ports.has(item.port))
    );
  }

  uncoveredObservations() {
    const selectedRisks = this.riskProfiles().filter((risk) => this.selectedRiskIds().includes(risk.id));
    return this.observations().filter((observation) =>
      this.selectedObservationIds().includes(observation.id) &&
      !selectedRisks.some((risk) => risk.port_services.length === 0 || risk.port_services.some((item) => item.port === observation.host_port))
    );
  }

  private syncStructureFromObservations() {
    const selectedId = this.selectedObservationIds()[0];
    const observation = this.observations().find((item) => item.id === selectedId);
    if (observation) this.syncStructureFromNetworkId(observation.network);
  }

  private errorMessage(error: any, fallback: string): string {
    const collect = (value: unknown): string[] => {
      if (typeof value === 'string') return [value];
      if (Array.isArray(value)) return value.flatMap(collect);
      if (value && typeof value === 'object') return Object.values(value as Record<string, unknown>).flatMap(collect);
      return [];
    };
    return collect(error?.error).join(' ') || fallback;
  }
}
