import { DatePipe } from '@angular/common';
import { Component, OnInit, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { ApiService } from '../../core/api/api.service';
import { Network, PeerObservation, RiskProfile } from '../../core/api/api.types';
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
          <p>Créer un bulletin à partir de peer observations et de profils de risque.</p>
        </div>
        <a class="btn secondary" routerLink="/soc-peers">Choisir des peers</a>
      </div>

      <section class="card">
        <h2>Informations bulletin</h2>
        <div class="grid cols-3">
          <label class="field">
            <span>ID structure</span>
            <input class="input" type="number" [(ngModel)]="structureId" />
          </label>
          <label class="field">
            <span>Réseau</span>
            <select class="select" [(ngModel)]="networkId">
              <option [ngValue]="null">Auto / multi-réseaux</option>
              @for (network of networks(); track network.id) {
                <option [ngValue]="network.id">#{{ network.id }} — {{ network.name }}</option>
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
                <tr><td colspan="9"><div class="empty">Aucune observation. Va sur SOC peers ou lance une recherche.</div></td></tr>
              }
            </tbody>
          </table>
        </div>
      </section>

      <section class="card">
        <h2>Profils de risque</h2>
        <div class="grid cols-2">
          @for (risk of riskProfiles(); track risk.id) {
            <label class="risk-card">
              <input type="checkbox" [checked]="selectedRiskIds().includes(risk.id)" (change)="toggleRisk(risk.id)" />
              <strong>{{ risk.name }}</strong>
              <span class="badge warning">{{ risk.default_severity }}</span>
              <small>Impact : {{ risk.impact }}</small>
              <small>Recommandation : {{ risk.recommendation }}</small>
            </label>
          } @empty {
            <p class="muted">Aucun profil de risque. Crée d’abord des RiskProfile côté backend/admin.</p>
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
  readonly observations = signal<PeerObservation[]>([]);
  readonly riskProfiles = signal<RiskProfile[]>([]);
  readonly selectedObservationIds = signal<number[]>([]);
  readonly selectedRiskIds = signal<number[]>([]);
  readonly message = signal('');
  readonly bytes = formatBytes;
  readonly duration = formatDuration;

  structureId = 1;
  networkId: number | null = null;
  externalReference = '';
  severity = '';
  status = 'draft';
  forceDuplicate = false;
  observationSearch = '';

  ngOnInit() {
    const ids = this.route.snapshot.queryParamMap.get('observations');
    if (ids) {
      this.selectedObservationIds.set(ids.split(',').map((value) => Number(value)).filter(Boolean));
    }
    this.api.networks().subscribe((data) => {
      this.networks.set(data.results);
      this.syncStructureFromNetwork();
    });
    this.api.riskProfiles({ is_active: true }).subscribe((data) => this.riskProfiles.set(data.results));
    this.loadObservations();
  }

  loadObservations() {
    this.api.peerObservationSuggestions({ peer_ip: this.observationSearch, limit: 50 }).subscribe((data) => {
      this.observations.set(data.results);
      this.syncStructureFromNetwork();
    });
  }

  toggleObservation(item: PeerObservation) {
    const selected = new Set(this.selectedObservationIds());
    selected.has(item.id) ? selected.delete(item.id) : selected.add(item.id);
    this.selectedObservationIds.set([...selected]);
    if (!this.networkId) {
      this.networkId = item.network;
      this.syncStructureFromNetwork();
    }
  }

  toggleRisk(id: number) {
    const selected = new Set(this.selectedRiskIds());
    selected.has(id) ? selected.delete(id) : selected.add(id);
    this.selectedRiskIds.set([...selected]);
  }

  canCreate() {
    return this.structureId && this.selectedObservationIds().length > 0 && this.selectedRiskIds().length > 0;
  }

  create() {
    const payload: Record<string, unknown> = {
      structure_id: this.structureId,
      network_id: this.networkId,
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

  private syncStructureFromNetwork() {
    if (!this.networkId) return;
    const network = this.networks().find((item) => item.id === this.networkId);
    if (network) {
      this.structureId = network.structure;
    }
  }
}
