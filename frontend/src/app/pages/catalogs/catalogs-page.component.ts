import { Component, OnInit, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ApiService, CatalogKind } from '../../core/api/api.service';
import { CatalogItem } from '../../core/api/api.types';

@Component({
  selector: 'app-catalogs-page',
  standalone: true,
  imports: [FormsModule],
  template: `
    <div class="page">
      <div class="page-title">
        <div><h1>Référentiels SOC</h1><p>Gérer les activités, risques et recommandations utilisés dans les bulletins.</p></div>
      </div>

      <section class="card">
        <div class="toolbar">
          @for (tab of tabs; track tab.kind) {
            <button class="btn" [class.secondary]="kind !== tab.kind" (click)="selectKind(tab.kind)">{{ tab.label }}</button>
          }
        </div>
      </section>

      <section class="card">
        <h2>{{ editingId ? 'Modifier' : 'Ajouter' }} — {{ currentLabel() }}</h2>
        <div class="grid cols-2">
          <label class="field"><span>Nom</span><input class="input" [(ngModel)]="name" /></label>
          <label class="field"><span>Description</span><textarea class="input" rows="3" [(ngModel)]="description"></textarea></label>
        </div>
        <div class="toolbar">
          <button class="btn" (click)="save()" [disabled]="!name.trim()">{{ editingId ? 'Enregistrer' : 'Créer' }}</button>
          @if (editingId) { <button class="btn secondary" (click)="resetForm()">Annuler</button> }
          @if (message()) { <span class="muted">{{ message() }}</span> }
        </div>
      </section>

      <section class="card">
        <div class="table-wrap">
          <table>
            <thead><tr><th>Nom</th><th>Description</th><th>État</th><th>Actions</th></tr></thead>
            <tbody>
              @for (item of items(); track item.id) {
                <tr>
                  <td><strong>{{ item.name }}</strong></td>
                  <td>{{ item.description || '-' }}</td>
                  <td><span class="badge" [class.success]="item.is_active">{{ item.is_active ? 'Actif' : 'Inactif' }}</span></td>
                  <td class="toolbar">
                    <button class="btn secondary" (click)="edit(item)">Modifier</button>
                    @if (item.is_active) {
                      <button class="btn secondary" (click)="deactivate(item)">Désactiver</button>
                    } @else {
                      <button class="btn secondary" (click)="reactivate(item)">Réactiver</button>
                    }
                  </td>
                </tr>
              } @empty { <tr><td colspan="4"><div class="empty">Aucun élément.</div></td></tr> }
            </tbody>
          </table>
        </div>
      </section>
    </div>
  `,
})
export class CatalogsPageComponent implements OnInit {
  private readonly api = inject(ApiService);
  readonly items = signal<CatalogItem[]>([]);
  readonly message = signal('');
  readonly tabs: Array<{ kind: CatalogKind; label: string }> = [
    { kind: 'activities', label: 'Activités' },
    { kind: 'risks', label: 'Risques' },
    { kind: 'recommendations', label: 'Recommandations' },
  ];
  kind: CatalogKind = 'activities';
  editingId: number | null = null;
  name = '';
  description = '';

  ngOnInit() { this.load(); }
  currentLabel() { return this.tabs.find((tab) => tab.kind === this.kind)?.label || ''; }
  selectKind(kind: CatalogKind) { this.kind = kind; this.resetForm(); this.load(); }
  load() {
    this.api.catalogItems(this.kind).subscribe({
      next: (data) => this.items.set(data.results),
      error: () => this.message.set('Chargement impossible.'),
    });
  }
  edit(item: CatalogItem) {
    this.editingId = item.id;
    this.name = item.name;
    this.description = item.description || '';
  }
  resetForm() { this.editingId = null; this.name = ''; this.description = ''; }
  save() {
    const payload = { name: this.name.trim(), description: this.description.trim(), is_active: true };
    const request = this.editingId
      ? this.api.updateCatalogItem(this.kind, this.editingId, payload)
      : this.api.createCatalogItem(this.kind, payload);
    request.subscribe({
      next: () => { this.message.set('Enregistré.'); this.resetForm(); this.load(); },
      error: (error) => this.message.set(this.errorMessage(error, 'Enregistrement impossible.')),
    });
  }
  deactivate(item: CatalogItem) {
    this.api.deactivateCatalogItem(this.kind, item.id).subscribe({
      next: () => { this.message.set('Élément désactivé.'); this.load(); },
      error: () => this.message.set('Désactivation impossible.'),
    });
  }
  reactivate(item: CatalogItem) {
    this.api.updateCatalogItem(this.kind, item.id, { is_active: true }).subscribe({
      next: () => { this.message.set('Élément réactivé.'); this.load(); },
      error: () => this.message.set('Réactivation impossible.'),
    });
  }
  private errorMessage(error: any, fallback: string) {
    const value = error?.error;
    if (typeof value === 'string') return value;
    if (value && typeof value === 'object') return Object.values(value).flat().join(' ');
    return fallback;
  }
}
