import { DatePipe } from '@angular/common';
import { Component, OnInit, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { ApiService, QueryParams } from '../../core/api/api.service';
import { AuthService } from '../../core/auth/auth.service';
import { DetectionHit, DetectionRule, FlowImport, Structure } from '../../core/api/api.types';
import { formatBytes, formatDuration } from '../../shared/formatters';

@Component({
  selector: 'app-detections-page',
  standalone: true,
  imports: [DatePipe, FormsModule, RouterLink],
  template: `
    <div class="page">
      <div class="page-title">
        <div>
          <h1>Détections SOC</h1>
          <p>Exécuter des règles simples sur les flows et examiner les signaux obtenus.</p>
        </div>
        <a class="btn secondary" routerLink="/workers">Suivre les jobs</a>
      </div>

      <section class="card">
        <h2>Lancer une détection</h2>
        <div class="filters">
          <label class="field">
            <span>Périmètre</span>
            <select class="select" [(ngModel)]="scope">
              <option value="structure">Une structure</option>
              <option value="import">Un import</option>
              <option value="date_range">Un intervalle de dates</option>
              <option value="all_flows">Tous les flows</option>
            </select>
          </label>
          @if (scope === 'structure' || scope === 'date_range') {
            <label class="field">
              <span>Structure</span>
              <select class="select" [(ngModel)]="structureId">
                @if (scope === 'date_range') {
                  <option [ngValue]="0">Toutes les structures</option>
                }
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
        </div>

        <div class="rule-grid">
          @for (rule of rules(); track rule.id) {
            <label class="rule-card">
              <input
                type="checkbox"
                [checked]="selectedRuleIds().includes(rule.id)"
                (change)="toggleRule(rule.id)"
              />
              <span>
                <strong>{{ rule.name }}</strong>
                <small>{{ rule.description }}</small>
                <small>Seuils : {{ ruleParameters(rule) }}</small>
              </span>
              <span class="badge" [class.danger]="rule.severity === 'critical'" [class.warning]="rule.severity === 'high'">
                {{ severityLabel(rule.severity) }}
              </span>
            </label>
            @if (isAdmin()) {
              <div class="rule-editor">
                <label><input type="checkbox" [(ngModel)]="rule.is_active" /> Active</label>
                <select class="select" [(ngModel)]="rule.severity">
                  <option value="low">Faible</option><option value="medium">Moyenne</option><option value="high">Élevée</option><option value="critical">Critique</option>
                </select>
                <textarea class="input" rows="3" [(ngModel)]="parameterDrafts[rule.id]" aria-label="Paramètres JSON"></textarea>
                <button class="btn secondary" (click)="saveRule(rule)">Enregistrer</button>
              </div>
            }
          }
        </div>
        @if (configMessage()) { <p class="muted">{{ configMessage() }}</p> }
        <div class="toolbar">
          <button class="btn" (click)="launchDetection()" [disabled]="selectedRuleIds().length === 0">
            Lancer les règles sélectionnées
          </button>
          @if (runMessage()) {
            <span class="muted">{{ runMessage() }}</span>
          }
        </div>
      </section>

      <section class="card">
        <h2>Signaux détectés</h2>
        <div class="filters">
          <label class="field">
            <span>Structure</span>
            <select class="select" [(ngModel)]="hitStructureId">
              <option [ngValue]="0">Toutes</option>
              @for (structure of structures(); track structure.id) {
                <option [ngValue]="structure.id">{{ structure.code }}</option>
              }
            </select>
          </label>
          <label class="field">
            <span>Statut</span>
            <select class="select" [(ngModel)]="hitStatus">
              <option value="">Tous</option>
              <option value="open">Ouvert</option>
              <option value="acknowledged">Pris en compte</option>
              <option value="dismissed">Ignoré</option>
            </select>
          </label>
          <label class="field">
            <span>Gravité</span>
            <select class="select" [(ngModel)]="hitSeverity">
              <option value="">Toutes</option>
              <option value="critical">Critique</option>
              <option value="high">Élevée</option>
              <option value="medium">Moyenne</option>
              <option value="low">Faible</option>
            </select>
          </label>
          <label class="field">
            <span>Peer IP</span>
            <input class="input" [(ngModel)]="hitPeerIp" placeholder="IP exacte" (keyup.enter)="loadHits()" />
          </label>
          <label class="field">
            <span>Classement</span>
            <select class="select" [(ngModel)]="hitOrdering">
              <option value="-last_seen_at">Plus récents</option>
              <option value="-severity">Gravité</option>
              <option value="-total_bytes">Volume</option>
              <option value="-total_duration_seconds">Durée</option>
              <option value="-flow_count">Nombre de flows</option>
            </select>
          </label>
          <button class="btn secondary" (click)="loadHits()">Filtrer</button>
        </div>

        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Date</th>
                <th>Gravité</th>
                <th>Règle</th>
                <th>Structure</th>
                <th>Hôte / port</th>
                <th>Peer</th>
                <th>Réputation</th>
                <th>Flows</th>
                <th>Volume</th>
                <th>Durée</th>
                <th>Statut</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              @for (hit of hits(); track hit.id) {
                <tr>
                  <td>{{ hit.observation_date | date:'mediumDate' }}</td>
                  <td><span class="badge" [class.danger]="hit.severity === 'critical'" [class.warning]="hit.severity === 'high'">{{ severityLabel(hit.severity) }}</span></td>
                  <td><strong>{{ hit.rule_name }}</strong><small class="summary">{{ hit.summary }}</small></td>
                  <td>{{ hit.structure_code }}</td>
                  <td>{{ hit.host_ip || '-' }}:{{ hit.host_port ?? '-' }}</td>
                  <td>{{ hit.peer_ip || '-' }} <small>{{ hit.peer_country || '' }}</small></td>
                  <td>{{ hit.reputation_verdict }} · {{ hit.reputation_score ?? '-' }}</td>
                  <td>{{ hit.flow_count }}</td>
                  <td>{{ bytes(hit.total_bytes) }}</td>
                  <td>{{ duration(hit.total_duration_seconds) }}</td>
                  <td>{{ statusLabel(hit.status) }}</td>
                  <td>
                    <div class="row-actions">
                      @if (hit.status !== 'acknowledged') {
                        <button class="btn secondary" (click)="setStatus(hit, 'acknowledged')">Prendre en compte</button>
                      }
                      @if (hit.status !== 'dismissed') {
                        <button class="btn secondary" (click)="setStatus(hit, 'dismissed')">Ignorer</button>
                      }
                      @if (hit.status !== 'open') {
                        <button class="btn secondary" (click)="setStatus(hit, 'open')">Rouvrir</button>
                      }
                    </div>
                  </td>
                </tr>
              } @empty {
                <tr><td colspan="12"><div class="empty">Aucun signal pour ces filtres.</div></td></tr>
              }
            </tbody>
          </table>
        </div>
      </section>

      <section class="card">
        <h2>Agrégats journaliers</h2>
        <p class="muted">Prépare les données historiques nécessaires à une future rétention. Cette action ne supprime aucun flow.</p>
        <div class="filters">
          <label class="field">
            <span>Structure</span>
            <select class="select" [(ngModel)]="aggregateStructureId">
              <option [ngValue]="0">Toutes les structures</option>
              @for (structure of structures(); track structure.id) {
                <option [ngValue]="structure.id">{{ structure.code }} — {{ structure.name }}</option>
              }
            </select>
          </label>
          <label class="field">
            <span>Date de début</span>
            <input class="input" type="date" [(ngModel)]="aggregateDateFrom" />
          </label>
          <label class="field">
            <span>Date de fin</span>
            <input class="input" type="date" [(ngModel)]="aggregateDateTo" />
          </label>
          <button class="btn secondary" (click)="launchAggregation()">Calculer les agrégats</button>
        </div>
        @if (aggregateMessage()) {
          <p class="muted">{{ aggregateMessage() }}</p>
        }
      </section>
    </div>
  `,
  styles: `
    .rule-grid { display: grid; gap: 10px; margin: 18px 0; }
    .rule-card {
      display: grid;
      grid-template-columns: auto 1fr auto;
      gap: 12px;
      align-items: start;
      padding: 12px;
      border: 1px solid var(--line);
      border-radius: 12px;
    }
    .rule-card span:nth-child(2), .summary { display: grid; gap: 5px; }
    .rule-card small, td small { display: block; color: var(--muted); margin-top: 4px; }
    .row-actions { display: grid; gap: 6px; min-width: 150px; }
    .row-actions .btn { white-space: nowrap; }
    .rule-editor { display: grid; grid-template-columns: auto 140px 1fr auto; gap: 10px; align-items: center; margin: -6px 0 10px 38px; }
    .rule-editor textarea { font-family: monospace; }
    @media (max-width: 900px) { .rule-editor { grid-template-columns: 1fr; margin-left: 0; } }
  `,
})
export class DetectionsPageComponent implements OnInit {
  private readonly api = inject(ApiService);
  private readonly auth = inject(AuthService);
  readonly rules = signal<DetectionRule[]>([]);
  readonly hits = signal<DetectionHit[]>([]);
  readonly structures = signal<Structure[]>([]);
  readonly imports = signal<FlowImport[]>([]);
  readonly selectedRuleIds = signal<number[]>([]);
  readonly runMessage = signal('');
  readonly aggregateMessage = signal('');
  readonly configMessage = signal('');
  parameterDrafts: Record<number, string> = {};
  readonly bytes = formatBytes;
  readonly duration = formatDuration;

  scope: 'structure' | 'import' | 'date_range' | 'all_flows' = 'structure';
  structureId = 0;
  importId = 0;
  dateFrom = '';
  dateTo = '';
  hitStructureId = 0;
  hitStatus = 'open';
  hitSeverity = '';
  hitPeerIp = '';
  hitOrdering = '-last_seen_at';
  aggregateStructureId = 0;
  aggregateDateFrom = this.localDate(-30);
  aggregateDateTo = this.localDate(0);

  ngOnInit() {
    this.api.structures({ is_active: true }).subscribe((data) => {
      this.structures.set(data.results);
      this.structureId = data.results[0]?.id || 0;
    });
    this.api.imports().subscribe((data) => {
      this.imports.set(data.results);
      this.importId = data.results[0]?.id || 0;
    });
    this.api.detectionRules().subscribe((data) => {
      this.rules.set(data.results);
      this.selectedRuleIds.set(data.results.filter((rule) => rule.is_active).map((rule) => rule.id));
      for (const rule of data.results) this.parameterDrafts[rule.id] = JSON.stringify(rule.parameters, null, 2);
    });
    this.loadHits();
  }

  toggleRule(id: number) {
    const selected = new Set(this.selectedRuleIds());
    selected.has(id) ? selected.delete(id) : selected.add(id);
    this.selectedRuleIds.set([...selected]);
  }

  isAdmin() { return this.auth.user()?.role === 'admin'; }

  saveRule(rule: DetectionRule) {
    try {
      const parameters = JSON.parse(this.parameterDrafts[rule.id] || '{}');
      this.api.updateDetectionRule(rule.id, { severity: rule.severity, is_active: rule.is_active, parameters }).subscribe({
        next: (updated) => {
          this.rules.update((items) => items.map((item) => item.id === updated.id ? updated : item));
          this.configMessage.set(`Règle « ${updated.name} » enregistrée.`);
        },
        error: (error) => this.configMessage.set(this.errorMessage(error, 'Configuration refusée.')),
      });
    } catch {
      this.configMessage.set('Les paramètres doivent être un objet JSON valide.');
    }
  }

  launchDetection() {
    const payload: Record<string, unknown> = {
      scope: this.scope,
      rule_ids: this.selectedRuleIds(),
    };
    if (this.scope === 'structure') payload['structure_id'] = this.structureId;
    if (this.scope === 'import') payload['import_id'] = this.importId;
    if (this.scope === 'date_range') {
      if (this.structureId) payload['structure_id'] = this.structureId;
      payload['date_from'] = this.normalizedDateTime(this.dateFrom);
      payload['date_to'] = this.normalizedDateTime(this.dateTo);
    }
    this.runMessage.set('Création du job...');
    this.api.launchDetection(payload).subscribe({
      next: ({ job, already_queued }) => this.runMessage.set(
        already_queued ? `Le job ${job.id} est déjà en attente.` : `Job ${job.id} créé. Le worker va exécuter les règles.`,
      ),
      error: (error) => this.runMessage.set(this.errorMessage(error, 'Impossible de lancer la détection.')),
    });
  }

  loadHits() {
    const params: QueryParams = {
      structure_id: this.hitStructureId || null,
      status: this.hitStatus,
      severity: this.hitSeverity,
      peer_ip: this.hitPeerIp,
      ordering: this.hitOrdering,
    };
    this.api.detectionHits(params).subscribe((data) => this.hits.set(data.results));
  }

  setStatus(hit: DetectionHit, status: DetectionHit['status']) {
    this.api.updateDetectionHitStatus(hit.id, status).subscribe(() => this.loadHits());
  }

  launchAggregation() {
    if (!this.aggregateDateFrom || !this.aggregateDateTo) {
      this.aggregateMessage.set('Les deux dates sont obligatoires.');
      return;
    }
    const payload: { date_from: string; date_to: string; structure_id?: number } = {
      date_from: this.aggregateDateFrom,
      date_to: this.aggregateDateTo,
    };
    if (this.aggregateStructureId) payload.structure_id = this.aggregateStructureId;
    this.aggregateMessage.set('Création du job...');
    this.api.launchDailyAggregation(payload).subscribe({
      next: ({ job, already_queued }) => this.aggregateMessage.set(
        already_queued ? `Le job ${job.id} est déjà en attente.` : `Job ${job.id} créé. Aucun flow ne sera supprimé.`,
      ),
      error: (error) => this.aggregateMessage.set(this.errorMessage(error, 'Impossible de lancer l’agrégation.')),
    });
  }

  ruleParameters(rule: DetectionRule): string {
    return Object.entries(rule.parameters)
      .map(([key, value]) => `${key}=${Array.isArray(value) ? value.join(',') : value}`)
      .join(' · ');
  }

  severityLabel(value: string): string {
    return ({ critical: 'Critique', high: 'Élevée', medium: 'Moyenne', low: 'Faible' } as Record<string, string>)[value] || value;
  }

  statusLabel(value: DetectionHit['status']): string {
    return ({ open: 'Ouvert', acknowledged: 'Pris en compte', dismissed: 'Ignoré' })[value];
  }

  private normalizedDateTime(value: string): string {
    return value && value.length === 16 ? `${value}:00` : value;
  }

  private localDate(offsetDays: number): string {
    const value = new Date();
    value.setDate(value.getDate() + offsetDays);
    const local = new Date(value.getTime() - value.getTimezoneOffset() * 60_000);
    return local.toISOString().slice(0, 10);
  }

  private errorMessage(error: any, fallback: string): string {
    const detail = error?.error;
    if (!detail || typeof detail !== 'object') return fallback;
    const first = Object.values(detail)[0];
    return Array.isArray(first) ? String(first[0]) : String(first || fallback);
  }
}
