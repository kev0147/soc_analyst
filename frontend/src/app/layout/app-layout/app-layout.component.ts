import { Component } from '@angular/core';
import { RouterOutlet } from '@angular/router';
import { SidebarComponent } from '../sidebar/sidebar.component';
import { TopbarComponent } from '../topbar/topbar.component';

@Component({
  selector: 'app-layout',
  standalone: true,
  imports: [RouterOutlet, SidebarComponent, TopbarComponent],
  template: `
    <div class="shell">
      <app-sidebar />
      <div class="main">
        <app-topbar />
        <section class="content">
          <router-outlet />
        </section>
      </div>
    </div>
  `,
  styles: `
    .shell {
      min-height: 100dvh;
      display: grid;
      grid-template-columns: 280px minmax(0, 1fr);
    }
    .main {
      min-width: 0;
      display: grid;
      grid-template-rows: auto 1fr;
    }
    .content {
      padding: 24px;
    }
    @media (max-width: 900px) {
      .shell { grid-template-columns: 1fr; }
    }
  `,
})
export class AppLayoutComponent {}
