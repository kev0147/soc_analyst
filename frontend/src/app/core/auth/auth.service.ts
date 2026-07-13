import { Injectable, computed, inject, signal } from '@angular/core';
import { Router } from '@angular/router';
import { catchError, of, tap } from 'rxjs';
import { ApiService } from '../api/api.service';
import { User } from '../api/api.types';

@Injectable({ providedIn: 'root' })
export class AuthService {
  private readonly api = inject(ApiService);
  private readonly router = inject(Router);
  private readonly userSignal = signal<User | null>(null);

  readonly user = this.userSignal.asReadonly();
  readonly isAuthenticated = computed(() => this.userSignal() !== null);

  bootstrap() {
    return this.api.me().pipe(
      tap((user) => this.userSignal.set(user)),
      catchError(() => {
        this.userSignal.set(null);
        return of(null);
      }),
    );
  }

  login(email: string, password: string) {
    return this.api.login(email, password).pipe(tap((user) => this.userSignal.set(user)));
  }

  logout() {
    this.api.logout().subscribe({
      next: () => {
        this.userSignal.set(null);
        this.router.navigateByUrl('/login');
      },
      error: () => {
        this.userSignal.set(null);
        this.router.navigateByUrl('/login');
      },
    });
  }
}
