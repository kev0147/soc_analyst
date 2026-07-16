import { Routes } from '@angular/router';
import { authGuard } from './core/guards/auth.guard';
import { AppLayoutComponent } from './layout/app-layout/app-layout.component';
import { LoginPageComponent } from './pages/login/login-page.component';
import { DashboardPageComponent } from './pages/dashboard/dashboard-page.component';
import { ImportsPageComponent } from './pages/imports/imports-page.component';
import { FlowsPageComponent } from './pages/flows/flows-page.component';
import { IpAnalysisPageComponent } from './pages/ip-analysis/ip-analysis-page.component';
import { SocPeersPageComponent } from './pages/soc-peers/soc-peers-page.component';
import { BulletinsPageComponent } from './pages/bulletins/bulletins-page.component';
import { BulletinCreatePageComponent } from './pages/bulletin-create/bulletin-create-page.component';
import { AnalysisPageComponent } from './pages/analysis/analysis-page.component';
import { StructuresPageComponent } from './pages/structures/structures-page.component';
import { WorkersPageComponent } from './pages/workers/workers-page.component';

export const routes: Routes = [
  { path: 'login', component: LoginPageComponent },
  {
    path: '',
    component: AppLayoutComponent,
    canActivate: [authGuard],
    children: [
      { path: '', pathMatch: 'full', redirectTo: 'dashboard' },
      { path: 'dashboard', component: DashboardPageComponent },
      { path: 'imports', component: ImportsPageComponent },
      { path: 'flows', component: FlowsPageComponent },
      { path: 'analysis', component: AnalysisPageComponent },
      { path: 'ip-analysis', component: IpAnalysisPageComponent },
      { path: 'soc-peers', component: SocPeersPageComponent },
      { path: 'bulletins', component: BulletinsPageComponent },
      { path: 'bulletins/new', component: BulletinCreatePageComponent },
      { path: 'structures', component: StructuresPageComponent },
      { path: 'workers', component: WorkersPageComponent },
    ],
  },
  { path: '**', redirectTo: 'dashboard' },
];
