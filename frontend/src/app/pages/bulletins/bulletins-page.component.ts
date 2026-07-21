import { DatePipe } from '@angular/common';
import { Component, OnInit, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { ApiService } from '../../core/api/api.service';
import { Bulletin, Structure } from '../../core/api/api.types';

@Component({
  selector: 'app-bulletins-page',
  standalone: true,
  imports: [DatePipe, FormsModule, RouterLink],
  template: `
    <div class="page">
      <div class="page-title">
        <div><h1>Bulletins</h1><p>Rechercher, filtrer et consulter les bulletins SOC.</p></div>
        <a class="btn" routerLink="/bulletins/new">Nouveau bulletin</a>
      </div>

      <section class="card filters">
        <label class="field search"><span>Recherche</span><input class="input" [(ngModel)]="search" placeholder="IP, référence interne ou externe" (keyup.enter)="applyFilters()" /></label>
        <label class="field"><span>Structure</span><select class="select" [(ngModel)]="structureId"><option [ngValue]="0">Toutes</option>@for (item of structures(); track item.id) {<option [ngValue]="item.id">{{ item.code }}</option>}</select></label>
        <label class="field"><span>Statut</span><select class="select" [(ngModel)]="status"><option value="">Tous</option><option value="draft">Brouillon</option><option value="sent">Envoyé</option></select></label>
        <label class="field"><span>Gravité</span><select class="select" [(ngModel)]="severity"><option value="">Toutes</option><option value="low">Faible</option><option value="medium">Moyenne</option><option value="high">Élevée</option><option value="critical">Critique</option></select></label>
        <label class="field"><span>Du</span><input class="input" type="date" [(ngModel)]="dateFrom" /></label>
        <label class="field"><span>Au</span><input class="input" type="date" [(ngModel)]="dateTo" /></label>
        <button class="btn" (click)="applyFilters()">Rechercher</button>
        <button class="btn secondary" (click)="resetFilters()">Réinitialiser</button>
      </section>

      <section class="card">
        <div class="list-summary"><strong>{{ count() }} bulletin(s)</strong><span class="muted">Page {{ page() }}</span></div>
        <div class="table-wrap">
          <table>
            <thead><tr><th>Référence</th><th>Structure</th><th>Gravité</th><th>Statut</th><th>IPs / peers</th><th>Risques</th><th>Date</th><th></th></tr></thead>
            <tbody>
              @for (bulletin of bulletins(); track bulletin.id) {
                <tr>
                  <td><strong>{{ bulletin.reference }}</strong>@if (bulletin.external_reference) {<br><span class="muted">{{ bulletin.external_reference }}</span>}</td>
                  <td><span class="badge info">{{ bulletin.structure_code }}</span><br><small class="muted">{{ bulletin.structure_name }}</small></td>
                  <td><span class="badge" [class.danger]="bulletin.severity === 'critical' || bulletin.severity === 'high'" [class.warning]="bulletin.severity === 'medium'">{{ severityLabel(bulletin.severity) }}</span></td>
                  <td><span class="badge" [class.success]="bulletin.status === 'sent'">{{ bulletin.status === 'sent' ? 'Envoyé' : 'Brouillon' }}</span></td>
                  <td><strong>{{ peerCount(bulletin) }}</strong> IP(s)<br><span class="muted preview">{{ peerPreview(bulletin) }}</span></td>
                  <td>{{ riskPreview(bulletin) }}</td>
                  <td>{{ (bulletin.sent_at || bulletin.created_at) | date:'dd/MM/yyyy' }}</td>
                  <td><a class="btn secondary compact" [routerLink]="['/bulletins', bulletin.id]">Voir</a></td>
                </tr>
              } @empty {<tr><td colspan="8"><div class="empty">Aucun bulletin ne correspond aux filtres.</div></td></tr>}
            </tbody>
          </table>
        </div>
        <div class="pagination">
          <button class="btn secondary" [disabled]="page() <= 1" (click)="changePage(page() - 1)">Précédent</button>
          <span>Page {{ page() }} / {{ totalPages() }}</span>
          <button class="btn secondary" [disabled]="page() >= totalPages()" (click)="changePage(page() + 1)">Suivant</button>
        </div>
      </section>
    </div>
  `,
  styles: `
    .filters .search { min-width: 280px; flex: 1; }
    .list-summary, .pagination { display:flex; justify-content:space-between; align-items:center; gap:12px; margin-bottom:12px; }
    .pagination { justify-content:flex-end; margin:16px 0 0; }
    .preview { display:inline-block; max-width:260px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
    .compact { display:inline-block; padding:7px 10px; }
  `,
})
export class BulletinsPageComponent implements OnInit {
  private readonly api = inject(ApiService);
  readonly bulletins = signal<Bulletin[]>([]);
  readonly structures = signal<Structure[]>([]);
  readonly count = signal(0);
  readonly page = signal(1);
  readonly totalPages = signal(1);
  search = '';
  structureId = 0;
  status = '';
  severity = '';
  dateFrom = '';
  dateTo = '';

  ngOnInit() {
    this.api.structures({ is_active: true }).subscribe((data) => this.structures.set(data.results));
    this.load();
  }

  load() {
    this.api.bulletins({ search: this.search.trim(), structure_id: this.structureId || null, status: this.status, severity: this.severity, date_from: this.dateFrom, date_to: this.dateTo, page: this.page() }).subscribe((data) => {
      this.bulletins.set(data.results);
      this.count.set(data.count);
      this.totalPages.set(Math.max(1, Math.ceil(data.count / 25)));
    });
  }
  applyFilters() { this.page.set(1); this.load(); }
  changePage(page: number) { this.page.set(page); this.load(); }
  resetFilters() { this.search = ''; this.structureId = 0; this.status = ''; this.severity = ''; this.dateFrom = ''; this.dateTo = ''; this.applyFilters(); }
  severityLabel(value: string) { return ({ low: 'Faible', medium: 'Moyenne', high: 'Élevée', critical: 'Critique' } as Record<string, string>)[value] || value; }
  peerIps(item: Bulletin) { return [...new Set([...(item.ips || []).map((ip) => ip.ip_address), ...(item.findings || []).map((finding) => finding.peer_ip)])]; }
  peerCount(item: Bulletin) { return this.peerIps(item).length; }
  peerPreview(item: Bulletin) { const ips = this.peerIps(item); return ips.slice(0, 3).join(', ') + (ips.length > 3 ? ` +${ips.length - 3}` : ''); }
  riskPreview(item: Bulletin) { const names = [...(item.risks || []).map((risk) => risk.name), ...(item.findings || []).map((finding) => finding.risk_name)]; return [...new Set(names)].slice(0, 2).join(', ') || '-'; }
}
