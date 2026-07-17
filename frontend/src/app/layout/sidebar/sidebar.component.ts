import { Component, inject } from '@angular/core';
import { RouterLink, RouterLinkActive } from '@angular/router';
import { AuthService } from '../../core/auth/auth.service';

@Component({
  selector: 'app-sidebar',
  standalone: true,
  imports: [RouterLink, RouterLinkActive],
  template: `
    <aside class="sidebar">
      <nav>
        @for (item of items; track item.path) {
          <a [routerLink]="item.path" routerLinkActive="active" [routerLinkActiveOptions]="{ exact: item.exact }">
            {{ item.label }}
          </a>
        }
        @if (auth.user()?.role === 'admin') {
          <a routerLink="/structures" routerLinkActive="active">Structures</a>
        }
      </nav>
    </aside>
  `,
  styles: `
    .sidebar {
      position: sticky;
      top: 0;
      height: 100dvh;
      padding: 20px;
      border-right: 1px solid var(--line);
      background: rgba(7, 16, 24, 0.86);
      backdrop-filter: blur(16px);
    }
    nav {
      display: grid;
      gap: 8px;
    }
    a {
      display: flex;
      align-items: center;
      color: var(--muted);
      padding: 11px 12px;
      border-radius: 12px;
      border: 1px solid transparent;
    }
    a.active,
    a:hover {
      color: var(--text);
      background: rgba(255, 255, 255, 0.05);
      border-color: var(--line);
    }
    @media (max-width: 900px) {
      .sidebar {
        position: relative;
        height: auto;
        border-right: 0;
        border-bottom: 1px solid var(--line);
      }
      nav {
        grid-template-columns: repeat(2, minmax(0, 1fr));
      }
    }
  `,
})
export class SidebarComponent {
  readonly auth = inject(AuthService);
  readonly items = [
    { path: '/dashboard', label: 'Dashboard', exact: true },
    { path: '/imports', label: 'Imports CSV', exact: true },
    { path: '/flows', label: 'Flows', exact: true },
    { path: '/analysis', label: 'Analyse SOC', exact: true },
    { path: '/detections', label: 'Détections', exact: true },
    { path: '/ip-analysis', label: 'Analyse IP', exact: true },
    { path: '/workers', label: 'Workers', exact: true },
    { path: '/soc-peers', label: 'Peers', exact: true },
    { path: '/bulletins', label: 'Bulletins', exact: true },
    { path: '/bulletins/new', label: 'Ajouter un bulletin', exact: true },
  ];
}
