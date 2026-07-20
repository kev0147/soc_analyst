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
  kind: 'flow_import' | 'ip_reputation' | 'detection' | 'daily_aggregation';
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
  detail?: string;
  already_running?: boolean;
}

export interface WorkerLogs {
  line_limit: number;
  files: Array<{ name: string; lines: string[] }>;
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

export interface MaliciousCommunicationRow {
  structure_id: number;
  structure_code: string;
  structure_name: string;
  host_ip: string;
  host_ports: number[];
  malicious_ip: string;
  reputation_verdict: 'malicious';
  reputation_score: number | null;
  peer_country: string;
  peer_ports: number[];
  services: string[];
  flow_count: number;
  total_bytes: number;
  total_duration_seconds: number;
  first_seen_at: string | null;
  last_seen_at: string | null;
  peer_observation_ids: number[];
}

export interface MaliciousCommunicationAnalysis {
  scope: 'structure' | 'import' | 'date_range';
  ordering: string;
  count: number;
  totals: {
    hosts: number;
    malicious_peers: number;
    correlations: number;
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
  activities?: Array<{ id: number; name: string }>;
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
  activity: number;
  activity_name: string;
  name: string;
  impact: string;
  recommendation: string;
  default_severity: 'low' | 'medium' | 'high' | 'critical';
  is_active: boolean;
  port_services: Array<{ id: number; port: number; service: string }>;
}

export interface PeerObservation {
  id: number;
  network: number;
  network_name: string;
  structure_id: number;
  structure_code: string;
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
  reputation_results: Array<{
    source: string;
    status: string;
    verdict: string;
    score: number | null;
    country: string;
    analyzed_at: string | null;
  }>;
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
  observation_ids: number[];
  observations: PeerInvestigationObservation[];
}

export interface PeerInvestigationObservation {
  id: number;
  network: number;
  structure_id: number;
  structure_code: string;
  host_ip: string | null;
  host_port: number | null;
  host_service: string;
  host_port_category: string;
  flow_count: number;
  total_bytes: number;
  total_packets: number;
  total_duration_seconds: number;
  first_seen_at: string | null;
  last_seen_at: string | null;
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

export interface DetectionRule {
  id: number;
  code: string;
  name: string;
  description: string;
  rule_type: 'long_ssh' | 'malicious_high_volume' | 'repeated_peer' | 'sensitive_port' | 'multi_host_peer';
  severity: 'low' | 'medium' | 'high' | 'critical';
  parameters: Record<string, unknown>;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export interface DetectionHit {
  id: number;
  rule: number;
  rule_code: string;
  rule_name: string;
  structure: number;
  structure_code: string;
  structure_name: string;
  network: number | null;
  network_name: string | null;
  status: 'open' | 'acknowledged' | 'dismissed';
  severity: 'low' | 'medium' | 'high' | 'critical';
  title: string;
  summary: string;
  observation_date: string;
  host_ip: string | null;
  peer_ip: string | null;
  host_port: number | null;
  peer_port: number | null;
  service: string;
  peer_country: string;
  reputation_verdict: 'malicious' | 'suspicious' | 'clean' | 'unknown';
  reputation_score: number | null;
  flow_count: number;
  host_count: number;
  total_bytes: number;
  total_packets: number;
  total_duration_seconds: number;
  first_seen_at: string | null;
  last_seen_at: string | null;
  evidence: Record<string, unknown>;
}

export interface DailyFlowAggregate {
  id: number;
  date: string;
  structure: number;
  structure_code: string;
  network: number;
  network_name: string;
  host_ip: string;
  peer_ip: string;
  host_port: number | null;
  peer_port: number | null;
  protocol: string;
  service: string;
  direction: string;
  peer_country: string;
  reputation_verdict: string;
  reputation_score: number | null;
  flow_count: number;
  total_bytes: number;
  total_packets: number;
  total_duration_seconds: number;
}
