import { Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import { AuthService } from '../../core/auth/auth.service';

@Component({
  selector: 'app-login-page',
  standalone: true,
  imports: [FormsModule],
  template: `
    <main class="login">
      <section class="card">
        <h1>Connexion</h1>

        <form (ngSubmit)="submit()">
          <label class="field">
            <span>Email</span>
            <input class="input" type="email" name="email" [(ngModel)]="email" required />
          </label>
          <label class="field">
            <span>Mot de passe</span>
            <input class="input" type="password" name="password" [(ngModel)]="password" required />
          </label>
          @if (error()) {
            <p class="error">{{ error() }}</p>
          }
          <button class="btn" type="submit" [disabled]="loading()">
            {{ loading() ? 'Connexion...' : 'Se connecter' }}
          </button>
        </form>
      </section>
    </main>
  `,
  styles: `
    .login {
      min-height: 100dvh;
      display: grid;
      place-items: center;
      padding: 24px;
    }
    .card {
      width: min(440px, 100%);
    }
    h1 {
      margin: 0 0 24px;
      font-size: 24px;
    }
    form {
      display: grid;
      gap: 14px;
    }
    .error {
      color: #fecaca;
      background: rgba(239, 68, 68, 0.13);
      border: 1px solid rgba(239, 68, 68, 0.25);
      border-radius: 12px;
      padding: 10px;
    }
  `,
})
export class LoginPageComponent {
  private readonly auth = inject(AuthService);
  private readonly router = inject(Router);
  readonly loading = signal(false);
  readonly error = signal('');

  email = '';
  password = '';

  submit() {
    this.loading.set(true);
    this.error.set('');
    this.auth.login(this.email, this.password).subscribe({
      next: () => this.router.navigateByUrl('/dashboard'),
      error: () => {
        this.error.set('Identifiants invalides ou serveur indisponible.');
        this.loading.set(false);
      },
    });
  }
}
