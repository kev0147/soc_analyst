import { Component, OnInit, inject, signal } from '@angular/core';
import { DatePipe } from '@angular/common';
import { RouterLink } from '@angular/router';
import { ApiService } from '../../core/api/api.service';
import { Bulletin } from '../../core/api/api.types';

@Component({
  selector: 'app-bulletins-page',
  standalone: true,
  imports: [DatePipe, RouterLink],
  template: `
    <div class="page">
      <div class="page-title">
        <div>
          <h1>Bulletins</h1>
          <p>Liste des bulletins, statuts, gravités, IPs et risques associés.</p>
        </div>
        <a class="btn" routerLink="/bulletins/new">Ajouter un bulletin</a>
      </div>

      <section class="card">
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Référence</th>
                <th>Gravité</th>
                <th>Status</th>
                <th>IPs</th>
                <th>Findings / risques</th>
                <th>Types</th>
                <th>Créé le</th>
              </tr>
            </thead>
            <tbody>
              @for (bulletin of bulletins(); track bulletin.id) {
                <tr>
                  <td>{{ bulletin.reference }}</td>
                  <td><span class="badge" [class.danger]="bulletin.severity === 'critical' || bulletin.severity === 'high'" [class.warning]="bulletin.severity === 'medium'">{{ bulletin.severity }}</span></td>
                  <td><span class="badge info">{{ bulletin.status }}</span></td>
                  <td>
                    @for (ip of bulletin.ips || []; track ip.ip_address) {
                      <span class="badge">{{ ip.role }}: {{ ip.ip_address }}</span>
                    }
                    @for (finding of bulletin.findings || []; track finding.id) {
                      <span class="badge">{{ finding.peer_ip }} → {{ finding.host_ip || '-' }}:{{ finding.host_port || '-' }}</span>
                    }
                  </td>
                  <td>
                    {{ names(bulletin.risks) }}
                    @if (bulletin.findings?.length) {
                      <div class="muted">{{ findingNames(bulletin.findings) }}</div>
                    }
                  </td>
                  <td>{{ names(bulletin.bulletin_types) }}</td>
                  <td>{{ bulletin.created_at | date:'medium' }}</td>
                </tr>
              } @empty {
                <tr><td colspan="7"><div class="empty">Aucun bulletin.</div></td></tr>
              }
            </tbody>
          </table>
        </div>
      </section>
    </div>
  `,
})
export class BulletinsPageComponent implements OnInit {
  private readonly api = inject(ApiService);
  readonly bulletins = signal<Bulletin[]>([]);

  ngOnInit() {
    this.api.bulletins().subscribe((data) => this.bulletins.set(data.results));
  }

  names(items?: Array<{ name: string }>) {
    return items?.map((item) => item.name).join(', ') || '-';
  }

  findingNames(items?: Array<{ risk_name: string }>) {
    return items?.map((item) => item.risk_name).join(', ') || '-';
  }
}
