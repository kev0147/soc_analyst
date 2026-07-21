import { DatePipe } from '@angular/common';
import { Component, OnInit, computed, inject, signal } from '@angular/core';
import { ActivatedRoute, RouterLink } from '@angular/router';
import { ApiService } from '../../core/api/api.service';
import { Bulletin } from '../../core/api/api.types';
import { formatBytes, formatDuration } from '../../shared/formatters';

interface BulletinPeerAggregate {
  peer_ip: string;
  country: string;
  verdict: string;
  score: number | null;
  hosts: Array<{ host_ip: string; ports: number[]; services: string[] }>;
  flow_count: number;
  total_bytes: number;
  total_packets: number;
  total_duration_seconds: number;
  risks: string[];
}

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
          <article class="card"><span class="muted">Peers</span><strong>{{ peerGroups().length }}</strong></article>
          <article class="card"><span class="muted">Volume total</span><strong>{{ bytes(totalBytes()) }}</strong></article>
          <article class="card"><span class="muted">Gravité</span><strong>{{ severityLabel(item.severity) }}</strong></article>
          <article class="card"><span class="muted">Statut</span><strong>{{ item.status === 'sent' ? 'Envoyé' : 'Brouillon' }}</strong></article>
          <article class="card"><span class="muted">Date</span><strong>{{ (item.sent_at || item.created_at) | date:'dd/MM/yyyy HH:mm' }}</strong></article>
        </section>

        <section class="card">
          <h2>Peers documentés</h2>
          <p class="muted">Une ligne par peer. Les volumes sont dédupliqués par observation.</p>
          <div class="table-wrap"><table><thead><tr><th>Peer / pays</th><th>Réputation</th><th>Hôtes avec leurs ports</th><th>Flows / paquets</th><th>Volume</th><th>Durée</th><th>Risques</th></tr></thead><tbody>
            @for (peer of peerGroups(); track peer.peer_ip) {
              <tr>
                <td><strong>{{ peer.peer_ip }}</strong><br><span class="muted">{{ peer.country || 'Pays inconnu' }}</span></td>
                <td><span class="badge" [class.danger]="peer.verdict === 'malicious'" [class.warning]="peer.verdict === 'suspicious'" [class.success]="peer.verdict === 'clean'">{{ peer.verdict }} · {{ peer.score ?? '-' }}</span></td>
                <td><details><summary>{{ peer.hosts.length }} hôte(s)</summary><ul class="host-list">@for (host of peer.hosts; track host.host_ip) {<li><strong>{{ host.host_ip }}</strong><span>Ports : {{ host.ports.join(', ') || '-' }}</span>@if (host.services.length) {<small>{{ host.services.join(', ') }}</small>}</li>}</ul></details></td>
                <td>{{ peer.flow_count }} / {{ peer.total_packets }}</td><td>{{ bytes(peer.total_bytes) }}</td><td>{{ duration(peer.total_duration_seconds) }}</td>
                <td>@for (risk of peer.risks; track risk) {<span class="badge warning">{{ risk }}</span>}</td>
              </tr>
            } @empty {<tr><td colspan="7" class="muted">Aucun peer lié à ce bulletin.</td></tr>}
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
    .summary-grid { display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:14px; }
    .summary-grid article { display:grid; gap:7px; }
    .summary-grid strong { font-size:20px; }
    .card .badge { margin:0 6px 6px 0; }
    details summary { cursor:pointer; color:var(--brand-2); font-weight:700; }
    .host-list { margin:10px 0 0; padding:0; list-style:none; display:grid; gap:8px; min-width:240px; }
    .host-list li { display:grid; gap:2px; padding-bottom:7px; border-bottom:1px solid var(--line); }
    .host-list span, .host-list small { color:var(--muted); }
    @media (max-width:980px) { .summary-grid { grid-template-columns:repeat(2,minmax(0,1fr)); } }
  `,
})
export class BulletinDetailPageComponent implements OnInit {
  private readonly api = inject(ApiService);
  private readonly route = inject(ActivatedRoute);
  readonly bulletin = signal<Bulletin | null>(null);
  readonly error = signal('');
  readonly peerGroups = computed(() => this.aggregatePeers(this.bulletin()));
  readonly totalBytes = computed(() => this.peerGroups().reduce((total, peer) => total + peer.total_bytes, 0));
  readonly bytes = formatBytes;
  readonly duration = formatDuration;
  ngOnInit() {
    const id = Number(this.route.snapshot.paramMap.get('id'));
    if (!id) { this.error.set('Identifiant de bulletin invalide.'); return; }
    this.api.bulletin(id).subscribe({ next: (item) => this.bulletin.set(item), error: () => this.error.set('Bulletin introuvable ou inaccessible.') });
  }
  severityLabel(value: string) { return ({ low: 'Faible', medium: 'Moyenne', high: 'Élevée', critical: 'Critique' } as Record<string, string>)[value] || value; }

  private aggregatePeers(bulletin: Bulletin | null): BulletinPeerAggregate[] {
    if (!bulletin) return [];
    const groups = new Map<string, BulletinPeerAggregate & { hostMap: Map<string, { ports: Set<number>; services: Set<string> }>; observations: Set<number> }>();
    const getGroup = (peerIp: string) => {
      let group = groups.get(peerIp);
      if (!group) {
        group = { peer_ip: peerIp, country: '', verdict: 'unknown', score: null, hosts: [], flow_count: 0, total_bytes: 0, total_packets: 0, total_duration_seconds: 0, risks: [], hostMap: new Map(), observations: new Set() };
        groups.set(peerIp, group);
      }
      return group;
    };
    for (const finding of bulletin.findings || []) {
      const group = getGroup(finding.peer_ip);
      group.country ||= finding.peer_country || '';
      if (this.verdictRank(finding.reputation_verdict) > this.verdictRank(group.verdict)) group.verdict = finding.reputation_verdict;
      if (finding.reputation_score !== null && finding.reputation_score !== undefined && (group.score === null || finding.reputation_score > group.score)) group.score = finding.reputation_score;
      const hostIp = finding.host_ip || 'Hôte inconnu';
      const host = group.hostMap.get(hostIp) || { ports: new Set<number>(), services: new Set<string>() };
      if (finding.host_port !== null) host.ports.add(finding.host_port);
      if (finding.host_service) host.services.add(finding.host_service);
      group.hostMap.set(hostIp, host);
      if (!group.observations.has(finding.peer_observation_id)) {
        group.observations.add(finding.peer_observation_id);
        group.flow_count += finding.flow_count;
        group.total_bytes += finding.total_bytes;
        group.total_packets += finding.total_packets;
        group.total_duration_seconds += finding.total_duration_seconds;
      }
      if (finding.risk_name && !group.risks.includes(finding.risk_name)) group.risks.push(finding.risk_name);
    }
    for (const ip of bulletin.ips || []) {
      const group = getGroup(ip.ip_address);
      const hostName = 'Ports documentés (historique)';
      const host = group.hostMap.get(hostName) || { ports: new Set<number>(), services: new Set<string>() };
      if (ip.port !== null) host.ports.add(ip.port);
      group.hostMap.set(hostName, host);
    }
    return [...groups.values()].map((group) => ({
      ...group,
      hosts: [...group.hostMap.entries()].map(([host_ip, values]) => ({ host_ip, ports: [...values.ports].sort((a, b) => a - b), services: [...values.services].sort() })),
      risks: [...group.risks].sort(),
    })).sort((a, b) => this.verdictRank(b.verdict) - this.verdictRank(a.verdict) || b.total_bytes - a.total_bytes);
  }

  private verdictRank(verdict: string) { return ({ malicious: 3, suspicious: 2, unknown: 1, clean: 0 } as Record<string, number>)[verdict] ?? 1; }
}
