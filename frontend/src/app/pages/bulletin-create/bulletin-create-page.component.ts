import { Component, OnInit, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { forkJoin } from 'rxjs';
import { ApiService } from '../../core/api/api.service';
import { Network, PeerObservation, RiskProfile, Structure } from '../../core/api/api.types';
import { formatBytes, formatDuration } from '../../shared/formatters';

interface BulletinPeerRow {
  peer_ip: string;
  country: string;
  verdict: string;
  score: number | null;
  host_ips: string[];
  host_ports: number[];
  flow_count: number;
  total_packets: number;
  total_bytes: number;
  total_duration_seconds: number;
}

interface BulletinDuplicate {
  reference: string;
  external_reference?: string;
  sent_at?: string | null;
  created_at?: string | null;
  matched_peer_ips?: string[];
}

@Component({
  selector: 'app-bulletin-create-page',
  standalone: true,
  imports: [FormsModule, RouterLink],
  template: `
    <div class="page">
      <div class="page-title">
        <div>
          <h1>Créer un bulletin</h1>
          <p>Sélectionne les peers à documenter. Tous leurs hôtes, ports et agrégats synchronisés seront inclus automatiquement.</p>
        </div>
        <a class="btn secondary" routerLink="/investigation">Choisir des peers</a>
      </div>

      <details class="card">
        <summary>Options avancées (facultatif)</summary>
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
      </details>

      <section class="card">
        <h2>Peers à inclure</h2>
        <div class="toolbar">
          <input class="input" [(ngModel)]="observationSearch" placeholder="Adresse IP peer exacte, ex: 203.0.113.10" (keyup.enter)="searchObservations()" />
          <button class="btn secondary" (click)="searchObservations()">Rechercher et ajouter le peer</button>
        </div>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th></th>
                <th>Peer / pays</th>
                <th>Réputation</th>
                <th>IP hôtes</th>
                <th>Ports hôtes</th>
                <th>Flows / paquets</th>
                <th>Volume</th>
                <th>Durée</th>
              </tr>
            </thead>
            <tbody>
              @for (item of peerRows(); track item.peer_ip) {
                <tr>
                  <td><input type="checkbox" [checked]="peerSelected(item)" (change)="togglePeer(item)" /></td>
                  <td>
                    <strong>{{ item.peer_ip }}</strong><br><span class="muted">{{ item.country || 'Pays inconnu' }}</span>
                  </td>
                  <td><span class="badge" [class.danger]="item.verdict === 'malicious'" [class.warning]="item.verdict === 'suspicious'" [class.success]="item.verdict === 'clean'">{{ item.verdict }} · {{ item.score ?? '-' }}</span></td>
                  <td>{{ item.host_ips.join(', ') || '-' }}</td>
                  <td>{{ item.host_ports.join(', ') || '-' }}</td>
                  <td>{{ item.flow_count }} / {{ item.total_packets }}</td>
                  <td>{{ bytes(item.total_bytes) }}</td>
                  <td>{{ duration(item.total_duration_seconds) }}</td>
                </tr>
              } @empty {
                <tr><td colspan="8"><div class="empty">Aucun peer ajouté. Recherche une adresse IP exacte ci-dessus ou sélectionne des peers dans <a routerLink="/investigation">Investigation</a>.</div></td></tr>
              }
            </tbody>
          </table>
        </div>
      </section>

      <section class="card">
        <h2>Qualification automatique</h2>
        <p class="muted">Les risques et activités sont déduits des ports. Le risque générique couvre automatiquement les ports inconnus.</p>
        <div class="toolbar">
          @for (risk of automaticRiskProfiles(); track risk.id) {
            <span class="badge" [class.warning]="isDefaultRisk(risk)">{{ risk.name }}</span>
          } @empty {
            <span class="muted">En attente de la sélection des peers.</span>
          }
        </div>
      </section>

      <section class="card toolbar">
        <label><input type="checkbox" [(ngModel)]="forceDuplicate" /> Forcer si doublon</label>
        <button class="btn" (click)="create()">Créer le bulletin</button>
        @if (creationBlockReason()) {
          <p class="badge warning">{{ creationBlockReason() }}</p>
        }
        @if (message()) {
          <p class="muted">{{ message() }}</p>
        }
      </section>

      @if (duplicateWarnings().length) {
        <section class="card">
          <h2>IPs déjà documentées</h2>
          <p class="muted">Ces IPs figurent dans des bulletins existants.</p>
          <div class="table-wrap">
            <table>
              <thead><tr><th>IP</th><th>Référence</th><th>Date</th></tr></thead>
              <tbody>
                @for (duplicate of duplicateWarnings(); track duplicate.reference) {
                  <tr>
                    <td>{{ duplicate.matched_peer_ips?.join(', ') || '-' }}</td>
                    <td>{{ duplicate.external_reference || duplicate.reference }}</td>
                    <td>{{ duplicateDate(duplicate) }}</td>
                  </tr>
                }
              </tbody>
            </table>
          </div>
          <button class="btn" (click)="createWithoutDuplicatePeers()">Créer uniquement avec les nouvelles IP</button>
        </section>
      }
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
  readonly peerRows = signal<BulletinPeerRow[]>([]);
  readonly riskProfiles = signal<RiskProfile[]>([]);
  readonly selectedObservationIds = signal<number[]>([]);
  readonly selectedPeerIps = signal<string[]>([]);
  readonly duplicateWarnings = signal<BulletinDuplicate[]>([]);
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
    const peers = (queryParams.get('peers') || '').split(',').map((value) => value.trim()).filter(Boolean);
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
    this.api.riskProfiles({ is_active: true, limit: 500 }).subscribe((data) => {
      this.riskProfiles.set(data.results);
    });
    if (this.selectedObservationIds().length) this.loadObservations();
    if (peers.length) this.addPeers(peers, false);
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
        const rows = this.groupObservations(merged);
        this.peerRows.set(rows);
        this.selectedPeerIps.set(rows.map((row) => row.peer_ip));
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
    const peerIps = this.observationSearch.split(/[\s,;]+/).map((value) => value.trim()).filter(Boolean);
    if (!peerIps.every((value) => this.isIpv4(value))) {
      this.message.set('Saisis une ou plusieurs adresses IPv4 valides.');
      return;
    }
    this.addPeers(peerIps, true);
  }

  private addPeers(peerIps: string[], announce: boolean) {
    const searches = peerIps.map((peerIp) => this.api.peerObservationSuggestions({
      peer_ip: peerIp,
      structure_id: this.structureId || null,
      limit: 500,
    }));
    forkJoin(searches).subscribe({
      next: (responses) => {
        const observations = responses.flatMap((data) => data.results);
        if (!observations.length) {
          this.message.set('Aucun peer trouvé pour ces adresses IP et cette structure.');
          return;
        }
        const rows = this.groupObservations(observations);
        const returnedIps = new Set(rows.map((row) => row.peer_ip));
        this.peerRows.set([...this.peerRows().filter((item) => !returnedIps.has(item.peer_ip)), ...rows]);
        this.selectedPeerIps.set([...new Set([...this.selectedPeerIps(), ...returnedIps])]);
        this.observations.set([
          ...this.observations().filter((item) => !returnedIps.has(item.peer_ip)),
          ...observations,
        ]);
        if (announce) this.message.set(`${rows.length} peer(s) ajouté(s).`);
      },
      error: (error) => this.message.set(this.errorMessage(error, 'Recherche impossible.')),
    });
  }

  toggleObservation(item: PeerObservation) {
    const selected = new Set(this.selectedObservationIds());
    selected.has(item.id) ? selected.delete(item.id) : selected.add(item.id);
    this.selectedObservationIds.set([...selected]);
    this.syncStructureFromNetworkId(item.network);
  }

  peerSelected(peer: BulletinPeerRow) {
    return this.selectedPeerIps().includes(peer.peer_ip);
  }

  togglePeer(peer: BulletinPeerRow) {
    const selected = new Set(this.selectedPeerIps());
    selected.has(peer.peer_ip) ? selected.delete(peer.peer_ip) : selected.add(peer.peer_ip);
    this.selectedPeerIps.set([...selected]);
  }

  creationBlockReason() {
    if (!this.structureId) return 'Sélectionne la structure du bulletin.';
    if (!this.selectedPeerIps().length) return 'Recherche et sélectionne au moins un peer.';
    if (!this.riskProfiles().length) return 'Les profils de risque ne sont pas encore chargés.';
    if (!this.effectiveRiskIds().length) return 'Le risque générique automatique est indisponible.';
    return '';
  }

  create() {
    const blockedBy = this.creationBlockReason();
    if (blockedBy) {
      this.message.set(blockedBy);
      return;
    }
    const payload: Record<string, unknown> = {
      structure_id: this.structureId,
      external_reference: this.externalReference,
      status: this.status,
      peer_ips: this.selectedPeerIps(),
      risk_profile_ids: this.effectiveRiskIds(),
      force_duplicate: this.forceDuplicate,
    };
    if (this.severity) {
      payload['severity'] = this.severity;
    }
    this.api.createBulletinFromFindings(payload).subscribe({
      next: () => this.router.navigateByUrl('/bulletins'),
      error: (error) => {
        if (error.status === 409) {
          const duplicates = Array.isArray(error?.error?.duplicates) ? error.error.duplicates : [];
          this.duplicateWarnings.set(duplicates);
          this.message.set('Certaines IPs sont déjà documentées. Tu peux créer le bulletin uniquement avec les nouvelles IP.');
        } else {
          this.message.set(this.errorMessage(error, 'Création impossible. Vérifie structure, observations et risques.'));
        }
      },
    });
  }

  createWithoutDuplicatePeers() {
    const duplicateIps = new Set(this.duplicateWarnings().flatMap((item) => item.matched_peer_ips || []));
    const newPeerIps = this.selectedPeerIps().filter((peerIp) => !duplicateIps.has(peerIp));
    if (!newPeerIps.length) {
      this.message.set('Toutes les IPs sélectionnées sont déjà documentées. Aucun nouveau bulletin n’est nécessaire.');
      return;
    }
    this.selectedPeerIps.set(newPeerIps);
    this.duplicateWarnings.set([]);
    this.forceDuplicate = false;
    this.create();
  }

  duplicateDate(duplicate: BulletinDuplicate) {
    const value = duplicate.sent_at || duplicate.created_at;
    return value ? new Intl.DateTimeFormat('fr-FR').format(new Date(value)) : '-';
  }

  private syncStructureFromNetworkId(networkId: number) {
    const network = this.networks().find((item) => item.id === networkId);
    if (network) {
      this.structureId = network.structure;
    }
  }

  automaticRiskProfiles() {
    const ports = new Set(
      this.peerRows()
        .filter((peer) => this.selectedPeerIps().includes(peer.peer_ip))
        .flatMap((peer) => peer.host_ports)
    );
    return this.riskProfiles().filter((risk) =>
      this.isDefaultRisk(risk) || risk.port_services.some((item) => ports.has(item.port))
    );
  }

  isDefaultRisk(risk: RiskProfile) {
    return risk.source_key === 'system-default-unclassified-risk';
  }

  private effectiveRiskIds() {
    return this.automaticRiskProfiles().map((risk) => risk.id);
  }

  private groupObservations(observations: PeerObservation[]): BulletinPeerRow[] {
    const grouped = new Map<string, BulletinPeerRow>();
    for (const item of observations) {
      let row = grouped.get(item.peer_ip);
      if (!row) {
        row = {
          peer_ip: item.peer_ip,
          country: item.peer_country || '',
          verdict: item.reputation_verdict,
          score: item.reputation_score ?? null,
          host_ips: [],
          host_ports: [],
          flow_count: 0,
          total_packets: 0,
          total_bytes: 0,
          total_duration_seconds: 0,
        };
        grouped.set(item.peer_ip, row);
      }
      if (item.host_ip && !row.host_ips.includes(item.host_ip)) row.host_ips.push(item.host_ip);
      if (item.host_port !== null && !row.host_ports.includes(item.host_port)) row.host_ports.push(item.host_port);
      row.flow_count += item.flow_count;
      row.total_packets += item.total_packets;
      row.total_bytes += item.total_bytes;
      row.total_duration_seconds += item.total_duration_seconds;
    }
    return [...grouped.values()].map((row) => ({
      ...row,
      host_ips: row.host_ips.sort(),
      host_ports: row.host_ports.sort((a, b) => a - b),
    }));
  }

  private isIpv4(value: string) {
    const parts = value.split('.');
    return parts.length === 4 && parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255);
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
