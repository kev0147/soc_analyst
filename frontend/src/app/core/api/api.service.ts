import { HttpClient, HttpParams } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import {
  Bulletin,
  CatalogItem,
  DashboardOverview,
  Flow,
  FlowImport,
  IpAnalysisRecord,
  Network,
  PaginatedResponse,
  PeerObservation,
  RiskProfile,
  TopPeer,
  User,
} from './api.types';

export type QueryParams = Record<string, string | number | boolean | null | undefined>;

@Injectable({ providedIn: 'root' })
export class ApiService {
  private readonly http = inject(HttpClient);
  private readonly baseUrl = this.resolveBaseUrl();

  login(email: string, password: string): Observable<User> {
    return this.http.post<User>(`${this.baseUrl}/auth/login/`, { email, password });
  }

  logout(): Observable<void> {
    return this.http.post<void>(`${this.baseUrl}/auth/logout/`, {});
  }

  me(): Observable<User> {
    return this.http.get<User>(`${this.baseUrl}/auth/me/`);
  }

  dashboard(params: QueryParams = {}): Observable<DashboardOverview> {
    return this.http.get<DashboardOverview>(`${this.baseUrl}/dashboard/overview/`, { params: this.params(params) });
  }

  imports(params: QueryParams = {}): Observable<PaginatedResponse<FlowImport>> {
    return this.http.get<PaginatedResponse<FlowImport>>(`${this.baseUrl}/flow-imports/`, { params: this.params(params) });
  }

  networks(params: QueryParams = {}): Observable<PaginatedResponse<Network>> {
    return this.http.get<PaginatedResponse<Network>>(`${this.baseUrl}/networks/`, { params: this.params(params) });
  }

  previewImport(networkId: number, file: File): Observable<unknown> {
    const form = new FormData();
    form.append('network_id', String(networkId));
    form.append('file', file);
    return this.http.post(`${this.baseUrl}/flow-imports/preview/`, form);
  }

  confirmImport(importId: number): Observable<FlowImport> {
    return this.http.post<FlowImport>(`${this.baseUrl}/flow-imports/confirm/`, { import_id: importId });
  }

  flows(params: QueryParams = {}): Observable<PaginatedResponse<Flow>> {
    return this.http.get<PaginatedResponse<Flow>>(`${this.baseUrl}/flows/`, { params: this.params(params) });
  }

  exportFlowsUrl(params: QueryParams = {}): string {
    const query = this.params(params).toString();
    return `${this.baseUrl}/flows/export/${query ? `?${query}` : ''}`;
  }

  bulletins(params: QueryParams = {}): Observable<PaginatedResponse<Bulletin>> {
    return this.http.get<PaginatedResponse<Bulletin>>(`${this.baseUrl}/bulletins/`, { params: this.params(params) });
  }

  createBulletin(payload: unknown): Observable<unknown> {
    return this.http.post(`${this.baseUrl}/bulletins/create/`, payload);
  }

  createBulletinFromFindings(payload: unknown): Observable<unknown> {
    return this.http.post(`${this.baseUrl}/bulletins/from-findings/`, payload);
  }

  risks(): Observable<PaginatedResponse<CatalogItem>> {
    return this.http.get<PaginatedResponse<CatalogItem>>(`${this.baseUrl}/risks/`);
  }

  bulletinTypes(): Observable<PaginatedResponse<CatalogItem>> {
    return this.http.get<PaginatedResponse<CatalogItem>>(`${this.baseUrl}/bulletin-types/`);
  }

  recommendations(): Observable<PaginatedResponse<CatalogItem>> {
    return this.http.get<PaginatedResponse<CatalogItem>>(`${this.baseUrl}/recommendations/`);
  }

  riskProfiles(params: QueryParams = {}): Observable<PaginatedResponse<RiskProfile>> {
    return this.http.get<PaginatedResponse<RiskProfile>>(`${this.baseUrl}/risk-profiles/`, { params: this.params(params) });
  }

  peerObservations(params: QueryParams = {}): Observable<PaginatedResponse<PeerObservation>> {
    return this.http.get<PaginatedResponse<PeerObservation>>(`${this.baseUrl}/peer-observations/`, { params: this.params(params) });
  }

  peerObservationSuggestions(params: QueryParams = {}): Observable<PaginatedResponse<PeerObservation>> {
    return this.http.get<PaginatedResponse<PeerObservation>>(`${this.baseUrl}/peer-observations/suggestions/`, { params: this.params(params) });
  }

  topPeers(params: QueryParams = {}): Observable<{ limit: number; sort: string; results: TopPeer[] }> {
    return this.http.get<{ limit: number; sort: string; results: TopPeer[] }>(`${this.baseUrl}/analytics/top-peers/`, { params: this.params(params) });
  }

  ipTimeline(ip: string, params: QueryParams = {}): Observable<unknown> {
    return this.http.get(`${this.baseUrl}/ips/${ip}/timeline/`, { params: this.params(params) });
  }

  // Contrat frontend préparé. Backend réputation à créer dans le bloc suivant.
  ipAnalysisRecords(params: QueryParams = {}): Observable<PaginatedResponse<IpAnalysisRecord>> {
    return this.http.get<PaginatedResponse<IpAnalysisRecord>>(`${this.baseUrl}/ip-analysis/records/`, { params: this.params(params) });
  }

  launchIpAnalysis(payload: { scope: 'all_flows' | 'import'; import_id?: number; tools: string[] }): Observable<unknown> {
    return this.http.post(`${this.baseUrl}/ip-analysis/run/`, payload);
  }

  private params(values: QueryParams): HttpParams {
    let params = new HttpParams();
    for (const [key, value] of Object.entries(values)) {
      if (value !== null && value !== undefined && value !== '') {
        params = params.set(key, String(value));
      }
    }
    return params;
  }

  private resolveBaseUrl(): string {
    if (typeof window !== 'undefined' && window.location.port === '4200') {
      return 'http://127.0.0.1:8000/api/v1';
    }
    return '/api/v1';
  }
}
