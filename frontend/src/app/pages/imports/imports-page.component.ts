import { Component, OnInit, inject, signal } from '@angular/core';
import { DatePipe } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ApiService } from '../../core/api/api.service';
import { FlowImport, Network } from '../../core/api/api.types';
import { formatBytes } from '../../shared/formatters';

@Component({
  selector: 'app-imports-page',
  standalone: true,
  imports: [DatePipe, FormsModule],
  template: `
    <div class="page">
      <div class="page-title">
        <div>
          <h1>Imports CSV</h1>
          <p>Ajouter un export SNA/Stealthwatch et suivre les imports existants.</p>
        </div>
        <button class="btn secondary" (click)="load()">Rafraîchir</button>
      </div>

      <section class="card">
        <h2>Upload CSV</h2>
        <div class="toolbar">
          <label class="field">
            <span>Réseau</span>
            <select class="select" [(ngModel)]="networkId">
              @for (network of networks(); track network.id) {
                <option [ngValue]="network.id">#{{ network.id }} — {{ network.name }}</option>
              }
            </select>
          </label>
          <label class="field">
            <span>Fichier CSV</span>
            <input class="input" type="file" accept=".csv,text/csv" (change)="selectFile($event)" />
          </label>
          <button class="btn" (click)="preview()" [disabled]="!file() || !networkId">Prévalider</button>
          @if (previewImportId()) {
            <button class="btn secondary" (click)="confirm()">Confirmer import #{{ previewImportId() }}</button>
          }
        </div>
        @if (message()) {
          <p class="muted">{{ message() }}</p>
        }
      </section>

      <section class="card">
        <h2>Liste des imports</h2>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>ID</th>
                <th>Status</th>
                <th>Fichier</th>
                <th>Taille</th>
                <th>Lignes</th>
                <th>Acceptées</th>
                <th>Rejetées</th>
                <th>Date import</th>
                <th>Début flows</th>
                <th>Fin flows</th>
              </tr>
            </thead>
            <tbody>
              @for (item of imports(); track item.id) {
                <tr>
                  <td>#{{ item.id }}</td>
                  <td><span class="badge" [class.success]="item.status === 'completed'" [class.warning]="item.status.includes('errors')" [class.danger]="item.status === 'failed'">{{ item.status }}</span></td>
                  <td>{{ item.original_filename }}</td>
                  <td>{{ bytes(item.file_size_bytes) }}</td>
                  <td>{{ item.total_rows }}</td>
                  <td>{{ item.accepted_rows }}</td>
                  <td>{{ item.rejected_rows }}</td>
                  <td>{{ item.uploaded_at | date:'medium' }}</td>
                  <td>{{ item.period_start ? (item.period_start | date:'medium') : '-' }}</td>
                  <td>{{ item.period_end ? (item.period_end | date:'medium') : '-' }}</td>
                </tr>
              } @empty {
                <tr><td colspan="10"><div class="empty">Aucun import.</div></td></tr>
              }
            </tbody>
          </table>
        </div>
      </section>
    </div>
  `,
})
export class ImportsPageComponent implements OnInit {
  private readonly api = inject(ApiService);
  readonly imports = signal<FlowImport[]>([]);
  readonly networks = signal<Network[]>([]);
  readonly file = signal<File | null>(null);
  readonly message = signal('');
  readonly previewImportId = signal<number | null>(null);
  readonly bytes = formatBytes;
  networkId = 1;

  ngOnInit() {
    this.load();
    this.api.networks().subscribe((data) => {
      this.networks.set(data.results);
      if (data.results.length) {
        this.networkId = data.results[0].id;
      }
    });
  }

  load() {
    this.api.imports().subscribe((data) => this.imports.set(data.results));
  }

  selectFile(event: Event) {
    const input = event.target as HTMLInputElement;
    this.file.set(input.files?.[0] ?? null);
    this.previewImportId.set(null);
  }

  preview() {
    const file = this.file();
    if (!file) return;
    this.message.set('Prévalidation en cours...');
    this.api.previewImport(this.networkId, file).subscribe({
      next: (result: any) => {
        this.previewImportId.set(result.import_id);
        this.message.set(result.is_valid ? 'Prévalidation OK. Tu peux confirmer.' : 'Prévalidation avec erreurs.');
        this.load();
      },
      error: () => this.message.set('Erreur pendant la prévalidation.'),
    });
  }

  confirm() {
    const id = this.previewImportId();
    if (!id) return;
    this.message.set('Import en cours...');
    this.api.confirmImport(id).subscribe({
      next: () => {
        this.message.set('Import confirmé.');
        this.previewImportId.set(null);
        this.load();
      },
      error: () => this.message.set('Erreur pendant la confirmation.'),
    });
  }
}
