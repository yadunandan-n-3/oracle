// ─── Dashboard ───────────────────────────────────────────────────────────

export interface DashboardData {
  missions: {
    total: number;
    active: number;
    completed: number;
    failed: number;
    by_status: Record<string, number>;
    by_type: Record<string, number>;
    recent: MissionSummary[];
  };
  assets: {
    total: number;
    by_type: Record<string, number>;
  };
  findings: {
    total: number;
    critical: number;
    high: number;
    by_severity: Record<string, number>;
    recent: FindingSummary[];
    top_cves: { cve_id: string; count: number }[];
    top_mitre_techniques: { technique: string; count: number }[];
  };
  risk: {
    average_risk_score: number;
    max_risk_score: number;
    overall_risk_level: "critical" | "high" | "medium" | "low" | "none";
    total_risk_scored_findings: number;
  };
  evidence: { total: number };
  system: {
    running: boolean;
    uptime_seconds: number;
    active_workflows: number;
    knowledge_graph_healthy: boolean;
  };
  generated_at: string;
}

// ─── Missions ────────────────────────────────────────────────────────────

export interface MissionSummary {
  id: string;
  name: string;
  status: string;
  mission_type: string;
  priority: string;
  total_assets: number;
  total_findings: number;
  critical_findings: number;
  high_findings: number;
  created_at: string;
  completed_at: string | null;
}

export interface MissionDetail extends MissionSummary {
  description: string;
  target_domains: string[];
  target_ip_ranges: string[];
  target_urls: string[];
  goals: string[];
  started_at: string | null;
  progress_percentage: number;
  duration_seconds: number;
  medium_findings: number;
  low_findings: number;
}

export interface CreateMissionRequest {
  name: string;
  description?: string;
  mission_type: string;
  priority?: string;
  target_domains?: string[];
  target_ip_ranges?: string[];
  target_urls?: string[];
  goals?: string[];
}

// ─── Assets ──────────────────────────────────────────────────────────────

export interface AssetSummary {
  id: string;
  value: string;
  label: string;
  asset_type: string;
  ip_addresses: string[];
  hostnames: string[];
  open_ports: number[];
  services: string[];
  technologies: string[];
  criticality: string;
  status: string;
}

// ─── Findings ────────────────────────────────────────────────────────────

export interface FindingSummary {
  id: string;
  title: string;
  severity: string;
  status: string;
  asset_value: string;
  cve_id: string | null;
  risk_score: number | null;
  mission_id: string;
  discovered_at: string | null;
}

export interface FindingDetail extends FindingSummary {
  description: string;
  cwe_id: string | null;
  cvss_score: number | null;
  cvss_vector: string;
  mitre_technique_id: string | null;
  mitre_tactic: string | null;
  remediation_steps: string[];
  remediation_effort: string;
  affected_component: string;
  affected_url: string;
  affected_port: number | null;
  business_impact: string;
  internet_exposed: boolean;
  authentication_required: boolean;
  confidence: number;
  risk_level: string;
  risk_factors: Array<{
    name: string;
    value: number;
    weight: number;
    evidence: string;
    source: string;
  }>;
  risk_explanation: {
    summary: string;
    reasoning: string;
    top_factors: string[];
  } | null;
  risk_calculation_metadata: {
    risk_id?: string | null;
    calculated_at?: string | null;
    calculated_by?: string | null;
    engine?: string | null;
  };
  intelligence_status: string;
  threat_intelligence: {
    cve?: { cve_id: string; cvss_score: number | null; description: string } | null;
    cwe?: { cwe_id: string; name: string; description: string } | null;
    owasp?: { owasp_id: string; category: string } | null;
    epss?: { epss_score: number; percentile: number } | null;
    kev?: { cve_id: string; vulnerability_name: string; required_action: string } | null;
    provider_status?: Record<string, string>;
  };
  evidence_ids: string[];
  tags: string[];
  updated_at: string;
}

// ─── Reports ─────────────────────────────────────────────────────────────

export interface ReportSummary {
  id: string;
  title: string;
  report_type: string;
  mission_id: string;
  mission_name: string;
  status: string;
  total_findings: number;
  critical_findings: number;
  high_findings: number;
  medium_findings: number;
  low_findings: number;
  risk_score: number | null;
  generated_at: string | null;
  created_at: string;
}

export interface ReportDetail extends ReportSummary {
  executive_summary: string;
  findings_summary: Record<string, number>;
  risk_level: string;
  critical_recommendations: string[];
  high_recommendations: string[];
  medium_recommendations: string[];
  low_recommendations: string[];
  total_assets: number;
  total_info: number;
  average_cvss: number | null;
  mission_duration_seconds: number | null;
  findings: FindingSummary[];
  assets: AssetSummary[];
}

// ─── Knowledge Graph ─────────────────────────────────────────────────────

export interface GraphNode {
  id: string;
  label: string;
  type: string;
  properties: Record<string, unknown>;
}

export interface GraphRelationship {
  source: string;
  target: string;
  type: string;
}

export interface GraphData {
  nodes: GraphNode[];
  relationships: GraphRelationship[];
  available: boolean;
}

// ─── Timeline ────────────────────────────────────────────────────────────

export interface PipelineStep {
  id: string;
  label: string;
  icon: string;
  description: string;
  status: "pending" | "in_progress" | "completed" | "failed";
  event_count: number;
  events: TimelineEvent[];
}

export interface TimelineEvent {
  timestamp: string;
  event_type: string;
  data: Record<string, unknown>;
  pipeline_step: string;
}

export interface MissionTimeline {
  mission_id: string;
  mission_name: string;
  mission_status: string;
  total_events: number;
  pipeline_steps: PipelineStep[];
  events: TimelineEvent[];
}

// ─── AI Copilot ──────────────────────────────────────────────────────────

export interface CopilotRequest {
  question: string;
  mission_id?: string;
  conversation_id?: string;
}

export interface CopilotResponse {
  answer: string;
  confidence: number;
  sources: string[];
  suggested_questions: string[];
  conversation_id: string;
}

// ─── Search ──────────────────────────────────────────────────────────────

export interface SearchResults {
  query: string;
  total_results: number;
  results: {
    missions: Array<Record<string, unknown>>;
    assets: Array<Record<string, unknown>>;
    findings: Array<Record<string, unknown>>;
    cves: Array<Record<string, unknown>>;
    mitre: Array<Record<string, unknown>>;
  };
}

// ─── Statistics ──────────────────────────────────────────────────────────

export interface OverviewStats {
  missions: {
    total: number;
    active: number;
    completed: number;
    failed: number;
    by_status: Record<string, number>;
  };
  assets: { total: number };
  findings: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    by_severity: Record<string, number>;
  };
  evidence: { total: number };
  system: Record<string, unknown>;
}

// ─── Benchmark ───────────────────────────────────────────────────────────

export interface BenchmarkResult {
  operation: string;
  duration_ms: number;
  success: boolean;
  error?: string;
  details: Record<string, unknown>;
}

export interface BenchmarkSummary {
  benchmark_results: BenchmarkResult[];
  summary: {
    total_operations: number;
    successful: number;
    failed: number;
    total_duration_ms: number;
    average_duration_ms: number;
    timestamp: string;
  };
}

// ─── Enums ───────────────────────────────────────────────────────────────

export type Severity = "critical" | "high" | "medium" | "low" | "informational";
export type FindingStatus = "open" | "in_progress" | "resolved" | "accepted" | "false_positive";
export type MissionStatus = "draft" | "pending" | "planning" | "in_progress" | "paused" | "completed" | "failed" | "cancelled";
export type RiskLevel = "critical" | "high" | "medium" | "low" | "none";

