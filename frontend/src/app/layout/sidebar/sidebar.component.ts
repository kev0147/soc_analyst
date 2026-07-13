import { Component } from '@angular/core';
import { RouterLink, RouterLinkActive } from '@angular/router';

@Component({
  selector: 'app-sidebar',
  standalone: true,
  imports: [RouterLink, RouterLinkActive],
  template: `
    <aside class="sidebar">
      <div class="brand">
        <div class="mark">D</div>
        <div>
          <strong>SOC Analyst</strong>
          <span>Flow investigation</span>
        </div>
      </div>

      <nav>
        @for (item of items; track item.path) {
          <a [routerLink]="item.path" routerLinkActive="active" [routerLinkActiveOptions]="{ exact: item.exact }">
            <span>{{ item.icon }}</span>
            {{ item.label }}
          </a>
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
    .brand {
      display: flex;
      align-items: center;
      gap: 12px;
      margin-bottom: 28px;
    }
    .mark {
      width: 42px;
      height: 42px;
      display: grid;
      place-items: center;
      border-radius: 14px;
      background: var(--brand);
      color: #211600;
      font-weight: 900;
    }
    .brand strong,
    .brand span {
      display: block;
    }
    .brand span {
      color: var(--muted);
      font-size: 12px;
      margin-top: 2px;
    }
    nav {
      display: grid;
      gap: 8px;
    }
    a {
      display: flex;
      align-items: center;
      gap: 10px;
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
  readonly items = [
    { path: '/dashboard', label: 'Dashboard', icon: '📊', exact: true },
    { path: '/imports', label: 'Imports CSV', icon: '⬆️', exact: true },
    { path: '/flows', label: 'Flows', icon: '🔎', exact: true },
    { path: '/ip-analysis', label: 'Analyse IP', icon: '🧪', exact: true },
    { path: '/soc-peers', label: 'SOC peers', icon: '🎯', exact: true },
    { path: '/bulletins', label: 'Bulletins', icon: '📣', exact: true },
    { path: '/bulletins/new', label: 'Ajouter bulletin', icon: '➕', exact: true },
  ];
}
