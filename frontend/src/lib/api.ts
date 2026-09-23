/**
 * ORACLE API Client
 *
 * Centralized HTTP client for all backend API interactions.
 * Uses the backend's REST API.
 */

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000/api";

// ─── Generic Fetch ───────────────────────────────────────────────────────

async function fetchAPI<T>(
  endpoint: string,
  options?: RequestInit
): Promise<T> {
  const url = `${API_BASE}${endpoint}`;
  const res = await fetch(url, {
    headers: {
      "Content-Type": "application/json",
      ...options?.headers,
    },
    ...options,
  });

  if (!res.ok) {
    const error = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(error.detail || `API Error: ${res.status}`);
  }

  const text = await res.text();
  if (!text) {
    return {} as T;
  }

  try {
    return JSON.parse(text) as T;
  } catch {
    return text as T;
  }
}

// ─── Dashboard ───────────────────────────────────────────────────────────

export async function getDashboard() {
  return fetchAPI<import("@/types").DashboardData>("/dashboard");
}

// ─── Missions ────────────────────────────────────────────────────────────

export async function listMissions(params?: {
  status?: string;
  mission_type?: string;
  limit?: number;
  offset?: number;
}) {
  const query = new URLSearchParams();
  if (params?.status) query.set("status", params.status);
  if (params?.mission_type) query.set("mission_type", params.mission_type);
  if (params?.limit) query.set("limit", String(params.limit));
  if (params?.offset) query.set("offset", String(params.offset));
  const qs = query.toString();

  const response = await fetchAPI<
    import("@/types").MissionSummary[] | {
      missions?: import("@/types").MissionSummary[];
      items?: import("@/types").MissionSummary[];
    }
  >(`/missions${qs ? `?${qs}` : ""}`);

  if (Array.isArray(response)) {
    return response;
  }

  return response.missions ?? response.items ?? [];
}

export async function getMission(id: string) {
  const mission = await fetchAPI<import("@/types").MissionDetail>(`/missions/${id}`);

  return {
    ...mission,
    target_domains: Array.isArray(mission.target_domains)
      ? mission.target_domains
      : [],
    target_ip_ranges: Array.isArray(mission.target_ip_ranges)
      ? mission.target_ip_ranges
      : [],
    target_urls: Array.isArray(mission.target_urls) ? mission.target_urls : [],
    goals: Array.isArray(mission.goals) ? mission.goals : [],
  };
}

export async function createMission(data: import("@/types").CreateMissionRequest) {
  return fetchAPI<import("@/types").MissionDetail>("/missions", {
    method: "POST",
    body: JSON.stringify(data),
  });
}

export async function executeMission(id: string) {
  return fetchAPI<{ status: string; mission_id: string }>(
    `/missions/${id}/execute`,
    { method: "POST" }
  );
}

export async function cancelMission(id: string) {
  return fetchAPI<{ status: string; mission_id: string }>(
    `/missions/${id}/cancel`,
    { method: "POST" }
  );
}

// ─── Assets ──────────────────────────────────────────────────────────────

export async function listMissionAssets(missionId: string, assetType?: string) {
  const query = assetType ? `?asset_type=${assetType}` : "";
  const response = await fetchAPI<import("@/types").AssetSummary[]>(
    `/assets/missions/${missionId}${query}`
  );

  return response.map((asset) => ({
    ...asset,
    ip_addresses: Array.isArray(asset.ip_addresses) ? asset.ip_addresses : [],
    hostnames: Array.isArray(asset.hostnames) ? asset.hostnames : [],
    open_ports: Array.isArray(asset.open_ports) ? asset.open_ports : [],
    services: Array.isArray(asset.services) ? asset.services : [],
    technologies: Array.isArray(asset.technologies) ? asset.technologies : [],
  }));
}

// ─── Findings ────────────────────────────────────────────────────────────

export async function listFindings(params?: {
  mission_id?: string;
  severity?: string;
  status?: string;
  limit?: number;
  offset?: number;
}) {
  const query = new URLSearchParams();
  if (params?.mission_id) query.set("mission_id", params.mission_id);
  if (params?.severity) query.set("severity", params.severity);
  if (params?.status) query.set("status", params.status);
  if (params?.limit) query.set("limit", String(params.limit));
  if (params?.offset) query.set("offset", String(params.offset));
  const qs = query.toString();
  return fetchAPI<{ total: number; findings: import("@/types").FindingSummary[] }>(
    `/findings${qs ? `?${qs}` : ""}`
  );
}

export async function getFinding(id: string) {
  return fetchAPI<import("@/types").FindingDetail>(`/findings/${id}`);
}

export async function getFindingsSummary(missionId?: string) {
  const query = missionId ? `?mission_id=${missionId}` : "";
  return fetchAPI<{
    total: number;
    by_severity: Record<string, number>;
    by_status: Record<string, number>;
  }>(`/findings/stats/summary${query}`);
}

// ─── Reports ─────────────────────────────────────────────────────────────

export async function listReports(params?: {
  mission_id?: string;
  report_type?: string;
  limit?: number;
}) {
  const query = new URLSearchParams();
  if (params?.mission_id) query.set("mission_id", params.mission_id);
  if (params?.report_type) query.set("report_type", params.report_type);
  if (params?.limit) query.set("limit", String(params.limit));
  const qs = query.toString();
  return fetchAPI<{ total: number; reports: import("@/types").ReportSummary[] }>(
    `/reports${qs ? `?${qs}` : ""}`
  );
}

export async function getReport(
  missionId: string,
  format: "json" | "html" = "json"
) {
  return fetchAPI<import("@/types").ReportDetail | { format: string; content: string }>(
    `/reports/${missionId}?format=${format}`
  );
}

// ─── Knowledge Graph ─────────────────────────────────────────────────────

export async function getMissionGraph(missionId: string) {
  return fetchAPI<import("@/types").GraphData>(
    `/graph/mission/${missionId}`
  );
}

export async function getAttackPaths(missionId: string, maxDepth = 5) {
  return fetchAPI<{ paths: unknown[]; available: boolean }>(
    `/graph/mission/${missionId}/attack-paths?max_depth=${maxDepth}`
  );
}

export async function getAssetConnections(missionId: string, assetId: string) {
  return fetchAPI<import("@/types").GraphData>(
    `/graph/mission/${missionId}/assets/${assetId}/connections`
  );
}

export async function getGraphSummary(missionId: string) {
  return fetchAPI<Record<string, unknown>>(
    `/graph/mission/${missionId}/summary`
  );
}

// ─── Timeline ────────────────────────────────────────────────────────────

export async function getMissionTimeline(missionId: string, limit = 200) {
  return fetchAPI<import("@/types").MissionTimeline>(
    `/timeline/mission/${missionId}?limit=${limit}`
  );
}

export async function getPipelineSteps() {
  return fetchAPI<{ pipeline_steps: import("@/types").PipelineStep[] }>(
    "/timeline/pipeline-steps"
  );
}

// ─── AI Copilot ──────────────────────────────────────────────────────────

export async function askCopilot(data: import("@/types").CopilotRequest) {
  return fetchAPI<import("@/types").CopilotResponse>("/copilot/ask", {
    method: "POST",
    body: JSON.stringify(data),
  });
}

// ─── Search ──────────────────────────────────────────────────────────────

export async function search(query: string, entityTypes?: string) {
  const params = new URLSearchParams({ q: query });
  if (entityTypes) params.set("entity_types", entityTypes);
  return fetchAPI<import("@/types").SearchResults>(
    `/search?${params.toString()}`
  );
}

// ─── Statistics ─────────────────────────────────────────────────────────

export async function getOverviewStats() {
  return fetchAPI<import("@/types").OverviewStats>("/statistics/overview");
}

export async function getRiskDistribution() {
  return fetchAPI<Record<string, unknown>>("/statistics/risk-distribution");
}

// ─── Benchmark ───────────────────────────────────────────────────────────

export async function runBenchmarks() {
  return fetchAPI<import("@/types").BenchmarkSummary>("/benchmark/run");
}

// ─── Auth ────────────────────────────────────────────────────────────────

export async function login(email: string, password: string) {
  return fetchAPI<{
    access_token: string;
    refresh_token: string;
    token_type: string;
  }>("/auth/login", {
    method: "POST",
    body: JSON.stringify({ email, password }),
  });
}

export async function register(data: {
  email: string;
  name?: string;
  password: string;
}) {
  return fetchAPI<{
    access_token: string;
    refresh_token: string;
    token_type: string;
  }>("/auth/register", {
    method: "POST",
    body: JSON.stringify(data),
  });
}

