import { Component, OnInit, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ApiService } from '../../core/api/api.service';
import { AuthService } from '../../core/auth/auth.service';
import { Network, NetworkCidr, Structure } from '../../core/api/api.types';

@Component({
  selector: 'app-structures-page',
  standalone: true,
  imports: [FormsModule],
  template: `
    <div class="page">
      <div class="page-title">
        <div>
          <h1>Structures et réseaux</h1>
          <p>Créer une structure, ses réseaux internes et les plages CIDR utilisées pour classifier les flows.</p>
        </div>
        <button class="btn secondary" (click)="loadStructures()">Rafraîchir</button>
      </div>

      @if (isAdmin()) {
        <section class="card">
          <h2>Ajouter une structure</h2>
          <div class="filters">
            <label class="field">
              <span>Nom</span>
              <input class="input" [(ngModel)]="structureName" />
            </label>
            <label class="field">
              <span>Code</span>
              <input class="input" [(ngModel)]="structureCode" placeholder="EXEMPLE" />
            </label>
            <label class="field">
              <span>Description</span>
              <input class="input" [(ngModel)]="structureDescription" />
            </label>
            <button class="btn" (click)="createStructure()" [disabled]="!structureName || !structureCode">Ajouter</button>
          </div>
        </section>
      }

      @if (message()) { <p class="muted">{{ message() }}</p> }

      <section class="card">
        <h2>Structures existantes</h2>
        <div class="table-wrap">
          <table>
            <thead><tr><th>Code</th><th>Nom</th><th>Description</th><th>État</th><th></th></tr></thead>
            <tbody>
              @for (structure of structures(); track structure.id) {
                <tr>
                  <td>{{ structure.code }}</td>
                  <td>{{ structure.name }}</td>
                  <td>{{ structure.description || '-' }}</td>
                  <td><span class="badge" [class.success]="structure.is_active">{{ structure.is_active ? 'active' : 'inactive' }}</span></td>
                  <td><button class="btn secondary" (click)="selectStructure(structure)">Configurer</button></td>
                </tr>
              } @empty {
                <tr><td colspan="5"><div class="empty">Aucune structure.</div></td></tr>
              }
            </tbody>
          </table>
        </div>
      </section>

      @if (selectedStructure(); as structure) {
        <section class="card">
          <h2>Réseaux de {{ structure.name }}</h2>
          @if (isAdmin()) {
            <div class="filters">
              <label class="field"><span>Nom du réseau</span><input class="input" [(ngModel)]="networkName" /></label>
              <label class="field"><span>Description</span><input class="input" [(ngModel)]="networkDescription" /></label>
              <button class="btn" (click)="createNetwork()" [disabled]="!networkName">Ajouter le réseau</button>
            </div>
          }
          <div class="network-list">
            @for (network of networks(); track network.id) {
              <button class="btn secondary" (click)="selectNetwork(network)">
                {{ network.name }}{{ selectedNetwork()?.id === network.id ? ' — sélectionné' : '' }}
              </button>
            } @empty {
              <div class="empty">Cette structure n’a encore aucun réseau.</div>
            }
          </div>
        </section>
      }

      @if (selectedNetwork(); as network) {
        <section class="card">
          <h2>Plages internes de {{ network.name }}</h2>
          @if (isAdmin()) {
            <div class="filters">
              <label class="field"><span>CIDR IPv4</span><input class="input" [(ngModel)]="cidr" placeholder="10.20.0.0/16" /></label>
              <label class="field"><span>Libellé</span><input class="input" [(ngModel)]="cidrLabel" /></label>
              <button class="btn" (click)="createCidr()" [disabled]="!cidr">Ajouter la plage</button>
            </div>
          }
          <div class="table-wrap">
            <table>
              <thead><tr><th>CIDR</th><th>Libellé</th></tr></thead>
              <tbody>
                @for (item of cidrs(); track item.id) {
                  <tr><td>{{ item.cidr }}</td><td>{{ item.label || '-' }}</td></tr>
                } @empty {
                  <tr><td colspan="2"><div class="empty">Aucune plage CIDR. Les flows ne pourront pas être rattachés à ce réseau.</div></td></tr>
                }
              </tbody>
            </table>
          </div>
        </section>
      }
    </div>
  `,
  styles: `
    .network-list { display: flex; flex-wrap: wrap; gap: 10px; margin-top: 16px; }
  `,
})
export class StructuresPageComponent implements OnInit {
  private readonly api = inject(ApiService);
  private readonly auth = inject(AuthService);
  readonly structures = signal<Structure[]>([]);
  readonly networks = signal<Network[]>([]);
  readonly cidrs = signal<NetworkCidr[]>([]);
  readonly selectedStructure = signal<Structure | null>(null);
  readonly selectedNetwork = signal<Network | null>(null);
  readonly message = signal('');

  structureName = '';
  structureCode = '';
  structureDescription = '';
  networkName = '';
  networkDescription = '';
  cidr = '';
  cidrLabel = '';

  ngOnInit() { this.loadStructures(); }

  isAdmin() { return this.auth.user()?.role === 'admin'; }

  loadStructures() {
    this.api.structures().subscribe({
      next: (data) => this.structures.set(data.results),
      error: () => this.message.set('Impossible de charger les structures.'),
    });
  }

  createStructure() {
    this.api.createStructure({
      name: this.structureName,
      code: this.structureCode.toUpperCase(),
      description: this.structureDescription,
    }).subscribe({
      next: (structure) => {
        this.structureName = '';
        this.structureCode = '';
        this.structureDescription = '';
        this.message.set('Structure ajoutée. Ajoute maintenant ses réseaux et CIDR.');
        this.loadStructures();
        this.selectStructure(structure);
      },
      error: (error) => this.message.set(this.apiError(error, 'Création impossible.')),
    });
  }

  selectStructure(structure: Structure) {
    this.selectedStructure.set(structure);
    this.selectedNetwork.set(null);
    this.cidrs.set([]);
    this.api.networks({ structure_id: structure.id }).subscribe((data) => this.networks.set(data.results));
  }

  createNetwork() {
    const structure = this.selectedStructure();
    if (!structure) return;
    this.api.createNetwork({ structure: structure.id, name: this.networkName, description: this.networkDescription }).subscribe({
      next: (network) => {
        this.networkName = '';
        this.networkDescription = '';
        this.message.set('Réseau ajouté. Configure au moins une plage CIDR.');
        this.selectStructure(structure);
        this.selectNetwork(network);
      },
      error: (error) => this.message.set(this.apiError(error, 'Création du réseau impossible.')),
    });
  }

  selectNetwork(network: Network) {
    this.selectedNetwork.set(network);
    this.api.networkCidrs({ network_id: network.id }).subscribe((data) => this.cidrs.set(data.results));
  }

  createCidr() {
    const network = this.selectedNetwork();
    if (!network) return;
    this.api.createNetworkCidr({ network: network.id, cidr: this.cidr, label: this.cidrLabel }).subscribe({
      next: () => {
        this.cidr = '';
        this.cidrLabel = '';
        this.message.set('Plage CIDR ajoutée.');
        this.selectNetwork(network);
      },
      error: (error) => this.message.set(this.apiError(error, 'Ajout du CIDR impossible.')),
    });
  }

  private apiError(error: any, fallback: string): string {
    const body = error?.error;
    if (!body || typeof body !== 'object') return fallback;
    const value = Object.values(body)[0];
    return Array.isArray(value) ? String(value[0]) : String(value || fallback);
  }
}
