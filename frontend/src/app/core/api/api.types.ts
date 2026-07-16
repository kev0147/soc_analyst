export interface PaginatedResponse<T> {
  count: number;
  next: string | null;
  previous: string | null;
  results: T[];
}

export interface User {
  id: number;
  email: string;
  display_name: string;
  role: 'admin' | 'analyst' | 'viewer';
}

export interface FlowImport {
  id: number;
  structure: number;
  status: string;
  original_filename: string;
  file_size_bytes: number;
  uploaded_at: string;
  period_start: string | null;
  period_end: string | null;
  total_rows: number;
  accepted_rows: number;
  inserted_flows: number;
  reused_flows: number;
  rejected_rows: number;
  latest_job?: BackgroundJob | null;
}

export interface BackgroundJob {
  id: string;
  kind: 'flow_import' | 'ip_reputation';
  status: 'queued' | 'running' | 'completed' | 'failed';
  status_message: string;
  progress_current: number;
  progress_total: number;
  progress_percent: number | null;
  error_message: string;
  can_retry: boolean;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  flow_import: number | null;
  result: Record<string, unknown>;
}

export interface WorkerStatus {
  status: 'running' | 'starting' | 'stopped' | 'offline';
  state: 'idle' | 'busy' | 'starting' | 'offline' | 'unknown' | 'invalid_status';
  pid: number | null;
  hostname: string;
  started_at: string | null;
  last_heartbeat_at: string | null;
  heartbeat_age_seconds: number | null;
  current_job_id: string | null;
  already_running?: boolean;
}

export interface Structure {
  id: number;
  name: string;
  code: string;
  description?: string;
  is_active?: boolean;
}

export interface Network {
  id: number;
  structure: number;
  name: string;
  description?: string;
  is_active?: boolean;
}

export interface Flow {
  id: number;
  sna_flow_id: string;
  started_at: string;
  ended_at: string | null;
  duration_seconds: number | null;
  direction: string;
  src_ip: string;
  src_hostname: string;
  src_port: number | null;
  dst_ip: string;
  dst_hostname: string;
  dst_port: number | null;
  protocol: string;
  service: string;
  application: string;
  total_bytes: number | null;
  total_packets: number | null;
}

export interface DashboardOverview {
  totals: {
    flows: number;
    total_bytes: number;
    total_packets: number;
    imports: number;
    bulletins: number;
    latest_flow_at: string | null;
  };
  top_malicious_ips_by_volume: MaliciousIpDashboardStat[];
  top_malicious_ips_by_duration: MaliciousIpDashboardStat[];
  top_hosts_with_malicious_by_volume: MaliciousHostDashboardStat[];
  top_hosts_with_malicious_by_duration: MaliciousHostDashboardStat[];
  top_talkers: Array<Record<string, unknown>>;
  top_conversations: Array<Record<string, unknown>>;
  top_ports_protocols: {
    ports: Array<Record<string, unknown>>;
    protocols: Array<Record<string, unknown>>;
  };
  latest_malicious_ips?: Array<Record<string, unknown>>;
  hosts_communicating_with_malicious?: Array<Record<string, unknown>>;
}

export interface NetworkCidr {
  id: number;
  network: number;
  cidr: string;
  label: string;
  created_at: string;
}

export interface MaliciousIpDashboardStat {
  ip_address: string;
  country: string;
  score: number | null;
  flow_count: number;
  total_bytes: number;
  total_duration_seconds: number;
  host_count: number;
  host_ips: string[];
  last_seen_at: string | null;
}

export interface MaliciousHostDashboardStat {
  host_ip: string;
  flow_count: number;
  total_bytes: number;
  total_duration_seconds: number;
  malicious_peer_count: number;
  malicious_ips: string[];
  last_seen_at: string | null;
}

export interface MaliciousCommunicationPeer {
  ip_address: string;
  country: string;
  score: number | null;
  ports: number[];
  host_ports: number[];
  services: string[];
  flow_count: number;
  total_bytes: number;
  total_duration_seconds: number;
  first_seen_at: string | null;
  last_seen_at: string | null;
}

export interface MaliciousCommunicationRow {
  host_ip: string;
  malicious_peer_count: number;
  malicious_peers: MaliciousCommunicationPeer[];
  countries: string[];
  peer_ports: number[];
  host_ports: number[];
  flow_count: number;
  total_bytes: number;
  total_duration_seconds: number;
  first_seen_at: string | null;
  last_seen_at: string | null;
}

export interface MaliciousCommunicationAnalysis {
  scope: 'structure' | 'import' | 'date_range';
  ordering: string;
  count: number;
  totals: {
    hosts: number;
    malicious_peers: number;
    flows: number;
    total_bytes: number;
    total_duration_seconds: number;
  };
  results: MaliciousCommunicationRow[];
}

export interface Bulletin {
  id: number;
  reference: string;
  severity: string;
  status: string;
  sent_at: string | null;
  created_at: string;
  ips?: Array<{ ip_address: string; role: string }>;
  risks?: Array<{ id: number; name: string }>;
  bulletin_types?: Array<{ id: number; name: string }>;
  recommendations?: Array<{ id: number; name: string; description?: string }>;
  findings?: BulletinFinding[];
}

export interface CatalogItem {
  id: number;
  name: string;
  description?: string;
  is_active?: boolean;
}

export interface RiskProfile {
  id: number;
  name: string;
  impact: string;
  recommendation: string;
  default_severity: 'low' | 'medium' | 'high' | 'critical';
  is_active: boolean;
}

export interface PeerObservation {
  id: number;
  network: number;
  peer_reputation: number;
  peer_ip: string;
  peer_country?: string;
  reputation_verdict: 'malicious' | 'suspicious' | 'clean' | 'unknown';
  reputation_score?: number | null;
  host_ip: string | null;
  host_port: number | null;
  host_service: string;
  host_port_category: string;
  first_seen_at: string | null;
  last_seen_at: string | null;
  flow_count: number;
  total_bytes: number;
  total_packets: number;
  total_duration_seconds: number;
  max_duration_seconds: number | null;
  avg_duration_seconds: number | null;
}

export interface BulletinFinding {
  id: number;
  peer_observation_id: number;
  peer_ip: string;
  peer_country?: string;
  host_ip: string | null;
  host_port: number | null;
  host_service: string;
  host_port_category: string;
  flow_count: number;
  total_bytes: number;
  total_packets: number;
  total_duration_seconds: number;
  reputation_verdict: string;
  reputation_score?: number | null;
  risk_profile_id: number;
  risk_name: string;
  severity: string;
  impact: string;
  recommendation: string;
}

export interface TopPeer {
  peer_ip: string;
  country: string;
  verdict: 'malicious' | 'suspicious' | 'clean' | 'unknown';
  score: number | null;
  source_count: number;
  successful_source_count: number;
  flow_count: number;
  total_bytes: number;
  total_packets: number;
  total_duration_seconds: number;
  max_duration_seconds: number | null;
  avg_duration_seconds: number | null;
  first_seen: string | null;
  last_seen: string | null;
  host_count: number;
  host_ips: string[];
  host_ports: number[];
  services: string[];
}

export interface IpAnalysisRecord {
  id: number;
  ip_address: string;
  country?: string;
  verdict: 'malicious' | 'suspicious' | 'clean' | 'unknown';
  score?: number | null;
  source_count: number;
  successful_source_count: number;
  flow_count: number;
  last_seen_at?: string | null;
  last_analyzed_at?: string | null;
  freshness_status: 'never_analyzed' | 'incomplete' | 'stale' | 'fresh';
  next_refresh_at?: string | null;
  results: Array<{
    source: 'abuseipdb' | 'virustotal';
    status: 'success' | 'skipped' | 'error' | 'never_analyzed';
    verdict: string;
    score?: number | null;
    country?: string;
    error_message?: string;
    analyzed_at?: string;
    expires_at?: string | null;
    is_stale: boolean;
    freshness_status: 'never_analyzed' | 'fresh' | 'stale' | 'error' | 'unavailable';
  }>;
}
