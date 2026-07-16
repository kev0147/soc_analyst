import { HttpClient, HttpParams } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import {
  Bulletin,
  BackgroundJob,
  CatalogItem,
  DashboardOverview,
  Flow,
  FlowImport,
  IpAnalysisRecord,
  MaliciousCommunicationAnalysis,
  Network,
  NetworkCidr,
  PaginatedResponse,
  PeerObservation,
  RiskProfile,
  Structure,
  TopPeer,
  User,
  WorkerStatus,
  WorkerLogs,
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

  structures(params: QueryParams = {}): Observable<PaginatedResponse<Structure>> {
    return this.http.get<PaginatedResponse<Structure>>(`${this.baseUrl}/structures/`, { params: this.params(params) });
  }

  createStructure(payload: { name: string; code: string; description?: string }): Observable<Structure> {
    return this.http.post<Structure>(`${this.baseUrl}/structures/create/`, payload);
  }

  createNetwork(payload: { structure: number; name: string; description?: string }): Observable<Network> {
    return this.http.post<Network>(`${this.baseUrl}/networks/create/`, payload);
  }

  networkCidrs(params: QueryParams = {}): Observable<PaginatedResponse<NetworkCidr>> {
    return this.http.get<PaginatedResponse<NetworkCidr>>(`${this.baseUrl}/network-cidrs/`, {
      params: this.params(params),
    });
  }

  createNetworkCidr(payload: { network: number; cidr: string; label?: string }): Observable<NetworkCidr> {
    return this.http.post<NetworkCidr>(`${this.baseUrl}/network-cidrs/create/`, payload);
  }

  previewImport(structureId: number, file: File): Observable<unknown> {
    const form = new FormData();
    form.append('structure_id', String(structureId));
    form.append('file', file);
    return this.http.post(`${this.baseUrl}/flow-imports/preview/`, form);
  }

  confirmImport(importId: number): Observable<{ job: BackgroundJob; flow_import: FlowImport; already_queued: boolean }> {
    return this.http.post<{ job: BackgroundJob; flow_import: FlowImport; already_queued: boolean }>(
      `${this.baseUrl}/flow-imports/confirm/`,
      { import_id: importId },
    );
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

  launchIpAnalysis(payload: { scope: 'all_flows' | 'import'; import_id?: number; tools: string[]; force_refresh?: boolean }): Observable<{ job: BackgroundJob; already_queued: boolean }> {
    return this.http.post<{ job: BackgroundJob; already_queued: boolean }>(`${this.baseUrl}/ip-analysis/run/`, payload);
  }

  maliciousCommunications(params: QueryParams): Observable<MaliciousCommunicationAnalysis> {
    return this.http.get<MaliciousCommunicationAnalysis>(`${this.baseUrl}/analytics/malicious-communications/`, {
      params: this.params(params),
    });
  }

  backgroundJobs(params: QueryParams = {}): Observable<PaginatedResponse<BackgroundJob>> {
    return this.http.get<PaginatedResponse<BackgroundJob>>(`${this.baseUrl}/background-jobs/`, { params: this.params(params) });
  }

  backgroundJob(id: string): Observable<BackgroundJob> {
    return this.http.get<BackgroundJob>(`${this.baseUrl}/background-jobs/${id}/`);
  }

  retryBackgroundJob(id: string): Observable<BackgroundJob> {
    return this.http.post<BackgroundJob>(`${this.baseUrl}/background-jobs/${id}/retry/`, {});
  }

  workerStatus(): Observable<WorkerStatus> {
    return this.http.get<WorkerStatus>(`${this.baseUrl}/workers/status/`);
  }

  startWorker(): Observable<WorkerStatus> {
    return this.http.post<WorkerStatus>(`${this.baseUrl}/workers/start/`, {});
  }

  workerLogs(lines = 100): Observable<WorkerLogs> {
    return this.http.get<WorkerLogs>(`${this.baseUrl}/workers/logs/`, {
      params: this.params({ lines }),
    });
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
      const hostname = window.location.hostname || '127.0.0.1';
      return `http://${hostname}:8000/api/v1`;
    }
    return '/api/v1';
  }
}
