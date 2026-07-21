import { DatePipe } from '@angular/common';
import { Component, OnInit, inject, signal } from '@angular/core';
import { ActivatedRoute, RouterLink } from '@angular/router';
import { ApiService } from '../../core/api/api.service';
import { Bulletin } from '../../core/api/api.types';
import { formatBytes, formatDuration } from '../../shared/formatters';

@Component({
  selector: 'app-bulletin-detail-page',
  standalone: true,
  imports: [DatePipe, RouterLink],
  template: `
    <div class="page">
      <div class="page-title">
        <div><a class="muted" routerLink="/bulletins">← Retour aux bulletins</a><h1>{{ bulletin()?.reference || 'Bulletin' }}</h1><p>{{ bulletin()?.external_reference || 'Aucune référence externe' }}</p></div>
        <a class="btn secondary" routerLink="/investigation">Nouvelle investigation</a>
      </div>

      @if (bulletin(); as item) {
        <section class="summary-grid">
          <article class="card"><span class="muted">Structure</span><strong>{{ item.structure_code }}</strong><small>{{ item.structure_name }}</small></article>
          <article class="card"><span class="muted">Gravité</span><strong>{{ severityLabel(item.severity) }}</strong></article>
          <article class="card"><span class="muted">Statut</span><strong>{{ item.status === 'sent' ? 'Envoyé' : 'Brouillon' }}</strong></article>
          <article class="card"><span class="muted">Date</span><strong>{{ (item.sent_at || item.created_at) | date:'dd/MM/yyyy HH:mm' }}</strong></article>
        </section>

        <section class="card">
          <h2>IPs et ports historiques</h2>
          <div class="table-wrap"><table><thead><tr><th>Rôle</th><th>Adresse IP</th><th>Port</th><th>Informations</th></tr></thead><tbody>
            @for (ip of item.ips || []; track ip.id) {<tr><td>{{ ip.role }}</td><td><strong>{{ ip.ip_address }}</strong></td><td>{{ ip.port ?? '-' }}</td><td>{{ ip.note || '-' }}</td></tr>}
            @empty {<tr><td colspan="4" class="muted">Aucune IP historique liée.</td></tr>}
          </tbody></table></div>
        </section>

        <section class="card">
          <h2>Constats d’investigation</h2>
          <div class="table-wrap"><table><thead><tr><th>Peer / pays</th><th>Hôte / port</th><th>Réputation</th><th>Volumes</th><th>Risque</th></tr></thead><tbody>
            @for (finding of item.findings || []; track finding.id) {
              <tr><td><strong>{{ finding.peer_ip }}</strong><br><span class="muted">{{ finding.peer_country || 'Pays inconnu' }}</span></td><td>{{ finding.host_ip || '-' }}:{{ finding.host_port ?? '-' }}<br><span class="muted">{{ finding.host_service || '-' }}</span></td><td><span class="badge" [class.danger]="finding.reputation_verdict === 'malicious'" [class.warning]="finding.reputation_verdict === 'suspicious'">{{ finding.reputation_verdict }} · {{ finding.reputation_score ?? '-' }}</span></td><td>{{ bytes(finding.total_bytes) }}<br><span class="muted">{{ finding.flow_count }} flows · {{ duration(finding.total_duration_seconds) }}</span></td><td><strong>{{ finding.risk_name }}</strong><br><span class="muted">{{ finding.risk_activity }}</span></td></tr>
            } @empty {<tr><td colspan="5" class="muted">Aucun constat synchronisé pour ce bulletin historique.</td></tr>}
          </tbody></table></div>
        </section>

        <section class="grid cols-3">
          <article class="card"><h2>Risques</h2>@for (risk of item.risks || []; track risk.id) {<span class="badge warning">{{ risk.name }}</span>}@for (finding of item.findings || []; track finding.id) {<p><strong>{{ finding.risk_name }}</strong></p><small class="muted">{{ finding.impact }}</small>}</article>
          <article class="card"><h2>Activités</h2>@for (activity of item.activities || []; track activity.id) {<span class="badge info">{{ activity.name }}</span>}@for (finding of item.findings || []; track finding.id) {@if (finding.risk_activity) {<p>{{ finding.risk_activity }}</p>}}</article>
          <article class="card"><h2>Recommandations</h2>@for (recommendation of item.recommendations || []; track recommendation.id) {<p><strong>{{ recommendation.name }}</strong><br><small class="muted">{{ recommendation.description }}</small></p>}@for (finding of item.findings || []; track finding.id) {@if (finding.recommendation) {<p>{{ finding.recommendation }}</p>}}</article>
        </section>
      } @else if (error()) {<div class="empty">{{ error() }}</div>} @else {<div class="empty">Chargement du bulletin…</div>}
    </div>
  `,
  styles: `
    .summary-grid { display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:14px; }
    .summary-grid article { display:grid; gap:7px; }
    .summary-grid strong { font-size:20px; }
    .card .badge { margin:0 6px 6px 0; }
    @media (max-width:980px) { .summary-grid { grid-template-columns:repeat(2,minmax(0,1fr)); } }
  `,
})
export class BulletinDetailPageComponent implements OnInit {
  private readonly api = inject(ApiService);
  private readonly route = inject(ActivatedRoute);
  readonly bulletin = signal<Bulletin | null>(null);
  readonly error = signal('');
  readonly bytes = formatBytes;
  readonly duration = formatDuration;
  ngOnInit() {
    const id = Number(this.route.snapshot.paramMap.get('id'));
    if (!id) { this.error.set('Identifiant de bulletin invalide.'); return; }
    this.api.bulletin(id).subscribe({ next: (item) => this.bulletin.set(item), error: () => this.error.set('Bulletin introuvable ou inaccessible.') });
  }
  severityLabel(value: string) { return ({ low: 'Faible', medium: 'Moyenne', high: 'Élevée', critical: 'Critique' } as Record<string, string>)[value] || value; }
}
