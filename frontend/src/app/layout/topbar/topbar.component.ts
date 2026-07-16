import { Component, inject } from '@angular/core';
import { AuthService } from '../../core/auth/auth.service';

@Component({
  selector: 'app-topbar',
  standalone: true,
  template: `
    <header class="topbar">
      <button class="btn secondary" (click)="auth.logout()">Déconnexion</button>
    </header>
  `,
  styles: `
    .topbar {
      display: flex;
      align-items: center;
      justify-content: flex-end;
      gap: 16px;
      padding: 16px 24px;
      border-bottom: 1px solid var(--line);
      background: rgba(7, 16, 24, 0.76);
      backdrop-filter: blur(16px);
    }
  `,
})
export class TopbarComponent {
  readonly auth = inject(AuthService);
}
