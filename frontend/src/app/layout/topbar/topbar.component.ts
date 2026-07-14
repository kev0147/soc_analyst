import { Component, Input, inject } from '@angular/core';
import { AuthService } from '../../core/auth/auth.service';
import { User } from '../../core/api/api.types';

@Component({
  selector: 'app-topbar',
  standalone: true,
  template: `
    <header class="topbar">
      <div class="user">
        @if (user) {
          <span class="badge info">{{ user.role }}</span>
          <span>{{ user.email }}</span>
          <button class="btn secondary" (click)="auth.logout()">Déconnexion</button>
        }
      </div>
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
    .user {
      display: flex;
      align-items: center;
      gap: 10px;
      color: var(--muted);
    }
  `,
})
export class TopbarComponent {
  @Input() user: User | null = null;
  readonly auth = inject(AuthService);
}
