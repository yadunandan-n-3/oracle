"use client";

import { useQuery } from "@tanstack/react-query";
import { getDashboard } from "@/lib/api";
import Layout from "@/components/layout/Layout";
import {
  Crosshair,
  Shield,
  AlertTriangle,
  TrendingUp,
  Target,
} from "lucide-react";

const severityColors: Record<string, string> = {
  critical: "text-red-400 bg-red-500/10 border-red-500/20",
  high: "text-orange-400 bg-orange-500/10 border-orange-500/20",
  medium: "text-yellow-400 bg-yellow-500/10 border-yellow-500/20",
  low: "text-blue-400 bg-blue-500/10 border-blue-500/20",
  informational: "text-slate-400 bg-slate-500/10 border-slate-500/20",
};

const statusColors: Record<string, string> = {
  completed: "text-emerald-400 bg-emerald-500/10",
  in_progress: "text-blue-400 bg-blue-500/10",
  failed: "text-red-400 bg-red-500/10",
  draft: "text-slate-400 bg-slate-500/10",
  planning: "text-yellow-400 bg-yellow-500/10",
};

export default function DashboardPage() {
  const { data, isLoading, error } = useQuery({
    queryKey: ["dashboard"],
    queryFn: getDashboard,
    refetchInterval: 15_000,
  });

  if (isLoading) {
    return (
      <Layout>
        <div className="p-6 space-y-6 animate-pulse">
          <div className="h-8 w-64 bg-slate-800 rounded" />
          <div className="grid grid-cols-4 gap-4">
            {[...Array(4)].map((_, i) => (
              <div key={i} className="h-28 bg-slate-800 rounded-xl" />
            ))}
          </div>
          <div className="h-64 bg-slate-800 rounded-xl" />
        </div>
      </Layout>
    );
  }

  if (error) {
    return (
      <Layout>
        <div className="p-6">
          <div className="bg-red-500/10 border border-red-500/20 rounded-xl p-6">
            <h2 className="text-red-400 font-semibold mb-2">
              Failed to load dashboard
            </h2>
            <p className="text-slate-400 text-sm">
              {(error as Error).message}
            </p>
          </div>
        </div>
      </Layout>
    );
  }

  if (!data) return null;

  const {
    missions,
    assets,
    findings,
    risk,
    evidence,
    system,
  } = data;

  const severityEntries = Object.entries(findings.by_severity || {}).filter(
    ([, count]) => Number(count) > 0
  );
  const hasFindings = severityEntries.length > 0;

  return (
    <Layout>
      <div className="p-6 space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-white">Dashboard</h1>
            <p className="text-sm text-slate-500 mt-1">
              Security Operations Overview
            </p>
          </div>
          <div className="flex items-center gap-2 text-xs text-slate-500">
            <div
              className={`h-2 w-2 rounded-full ${
                system.running ? "bg-emerald-400" : "bg-red-400"
              }`}
            />
            <span>{system.running ? "System Online" : "System Offline"}</span>
            {system.knowledge_graph_healthy && (
              <>
                <span className="text-slate-700">·</span>
                <span>Graph Connected</span>
              </>
            )}
          </div>
        </div>

        {/* KPI Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <KPICard
            icon={Crosshair}
            label="Active Missions"
            value={missions.active}
            total={missions.total}
            color="text-blue-400"
            bgColor="bg-blue-500/10"
          />
          <KPICard
            icon={Shield}
            label="Total Assets"
            value={assets.total}
            color="text-emerald-400"
            bgColor="bg-emerald-500/10"
          />
          <KPICard
            icon={AlertTriangle}
            label="Critical Findings"
            value={findings.critical}
            total={findings.total}
            color="text-red-400"
            bgColor="bg-red-500/10"
            alert={findings.critical > 0}
          />
          <KPICard
            icon={TrendingUp}
            label="Risk Score"
            value={risk.max_risk_score.toFixed(0)}
            suffix="/100"
            color={
              risk.overall_risk_level === "critical"
                ? "text-red-400"
                : risk.overall_risk_level === "high"
                ? "text-orange-400"
                : "text-emerald-400"
            }
            bgColor="bg-purple-500/10"
          />
        </div>

        {/* Main content grid */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Findings by Severity */}
          <div className="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-xl p-5">
            <h2 className="text-sm font-semibold text-white mb-4">
              Findings by Severity
            </h2>
            <div className="space-y-3">
              {!hasFindings ? (
                <div className="rounded-lg border border-dashed border-slate-800 bg-slate-950/50 px-4 py-6 text-center text-sm text-slate-500">
                  No findings have been recorded yet. Run a mission to populate the dashboard.
                </div>
              ) : (
                severityEntries.map(([severity, count]) => {
                const maxCount = Math.max(
                  ...severityEntries.map(([, entryCount]) => Number(entryCount)),
                  1
                );
                const percentage = (count / maxCount) * 100;
                const barColor = severityColors[severity]?.split(" ")[0] || "text-slate-400";
                const barBg =
                  severity === "critical"
                    ? "bg-red-500"
                    : severity === "high"
                    ? "bg-orange-500"
                    : severity === "medium"
                    ? "bg-yellow-500"
                    : severity === "low"
                    ? "bg-blue-500"
                    : "bg-slate-500";

                return (
                  <div key={severity} className="space-y-1">
                    <div className="flex items-center justify-between text-sm">
                      <span className="capitalize text-slate-300">
                        {severity}
                      </span>
                      <span className={`font-medium ${barColor}`}>
                        {count}
                      </span>
                    </div>
                    <div className="h-2 bg-slate-800 rounded-full overflow-hidden">
                      <div
                        className={`h-full ${barBg} rounded-full transition-all duration-500`}
                        style={{ width: `${percentage}%` }}
                      />
                    </div>
                  </div>
                );
              })
              )}
            </div>
          </div>

          {/* Risk Overview */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
            <h2 className="text-sm font-semibold text-white mb-4">
              Risk Overview
            </h2>
            <div className="space-y-4">
              <div className="text-center">
                <div className="text-4xl font-bold text-white mb-1">
                  {risk.max_risk_score.toFixed(0)}
                </div>
                <div className="text-xs text-slate-500">Max Risk Score</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-semibold text-slate-300 mb-1">
                  {risk.average_risk_score.toFixed(1)}
                </div>
                <div className="text-xs text-slate-500">Average Risk Score</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-semibold text-slate-300 mb-1">
                  {evidence.total}
                </div>
                <div className="text-xs text-slate-500">Evidence Items</div>
              </div>
            </div>
          </div>
        </div>

        {/* Recent Missions */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl">
          <div className="px-5 py-4 border-b border-slate-800 flex items-center justify-between">
            <h2 className="text-sm font-semibold text-white">
              Recent Missions
            </h2>
            <span className="text-xs text-slate-500">
              {missions.total} total
            </span>
          </div>
          <div className="divide-y divide-slate-800">
            {missions.recent.length === 0 ? (
              <div className="px-5 py-8 text-center text-sm text-slate-500">
                No missions yet. Create your first mission to get started.
              </div>
            ) : (
              missions.recent.map((mission) => (
                <a
                  key={mission.id}
                  href={`/missions/${mission.id}`}
                  className="flex items-center justify-between px-5 py-3 hover:bg-slate-800/50 transition-colors"
                >
                  <div className="flex items-center gap-3">
                    <Target className="h-4 w-4 text-slate-500" />
                    <div>
                      <p className="text-sm font-medium text-white">
                        {mission.name}
                      </p>
                      <p className="text-xs text-slate-500">
                        {mission.mission_type.replace(/_/g, " ")}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-4 text-xs">
                    <span className="text-slate-500">
                      {mission.total_findings} findings
                    </span>
                    {mission.critical_findings > 0 && (
                      <span className="text-red-400 font-medium">
                        {mission.critical_findings} critical
                      </span>
                    )}
                    <span
                      className={`px-2 py-0.5 rounded text-xs font-medium ${
                        statusColors[mission.status] ||
                        "text-slate-400 bg-slate-500/10"
                      }`}
                    >
                      {mission.status.replace(/_/g, " ")}
                    </span>
                  </div>
                </a>
              ))
            )}
          </div>
        </div>

        {/* Recent Findings */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl">
          <div className="px-5 py-4 border-b border-slate-800 flex items-center justify-between">
            <h2 className="text-sm font-semibold text-white">
              Recent Findings
            </h2>
            <a
              href="/findings"
              className="text-xs text-emerald-400 hover:text-emerald-300"
            >
              View all
            </a>
          </div>
          <div className="divide-y divide-slate-800">
            {findings.recent.length === 0 ? (
              <div className="px-5 py-8 text-center text-sm text-slate-500">
                No findings yet. Findings appear after missions are executed.
              </div>
            ) : (
              findings.recent.map((finding) => (
                <a
                  key={finding.id}
                  href={`/findings/${finding.id}`}
                  className="flex items-center justify-between px-5 py-3 hover:bg-slate-800/50 transition-colors"
                >
                  <div className="flex items-center gap-3 min-w-0">
                    <span
                      className={`px-2 py-0.5 rounded text-xs font-medium ${
                        severityColors[finding.severity] ||
                        "text-slate-400 bg-slate-500/10"
                      }`}
                    >
                      {finding.severity}
                    </span>
                    <div className="min-w-0">
                      <p className="text-sm font-medium text-white truncate">
                        {finding.title}
                      </p>
                      <p className="text-xs text-slate-500 truncate">
                        {finding.asset_value}
                        {finding.cve_id && (
                          <span className="ml-2 text-red-400">
                            {finding.cve_id}
                          </span>
                        )}
                      </p>
                    </div>
                  </div>
                  {finding.risk_score !== null && (
                    <span className="text-xs font-medium text-slate-400 flex-shrink-0 ml-4">
                      Risk: {finding.risk_score.toFixed(1)}
                    </span>
                  )}
                </a>
              ))
            )}
          </div>
        </div>

        {/* Top CVEs */}
        {findings.top_cves.length > 0 && (
          <div className="bg-slate-900 border border-slate-800 rounded-xl">
            <div className="px-5 py-4 border-b border-slate-800">
              <h2 className="text-sm font-semibold text-white">
                Top CVEs by Frequency
              </h2>
            </div>
            <div className="divide-y divide-slate-800">
              {findings.top_cves.map((cve) => (
                <div
                  key={cve.cve_id}
                  className="flex items-center justify-between px-5 py-3"
                >
                  <span className="text-sm font-mono text-red-400">
                    {cve.cve_id}
                  </span>
                  <span className="text-xs text-slate-500">
                    {cve.count} finding{cve.count > 1 ? "s" : ""}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </Layout>
  );
}

function KPICard({
  icon: Icon,
  label,
  value,
  total,
  suffix,
  color,
  bgColor,
  alert,
}: {
  icon: React.ElementType;
  label: string;
  value: string | number;
  total?: number;
  suffix?: string;
  color: string;
  bgColor: string;
  alert?: boolean;
}) {
  return (
    <div className="relative bg-slate-900 border border-slate-800 rounded-xl p-5 hover:border-slate-700 transition-colors">
      {alert && (
        <div className="absolute -top-1 -right-1 h-3 w-3 bg-red-500 rounded-full animate-pulse" />
      )}
      <div className="flex items-center justify-between mb-3">
        <div className={`${bgColor} p-2 rounded-lg`}>
          <Icon className={`h-5 w-5 ${color}`} />
        </div>
      </div>
      <div className={`text-2xl font-bold text-white ${color}`}>
        {value}
        {suffix && <span className="text-sm text-slate-500 ml-1">{suffix}</span>}
      </div>
      <div className="text-xs text-slate-500 mt-1">
        {label}
        {total !== undefined && (
          <span className="ml-1">
            · {total} total
          </span>
        )}
      </div>
    </div>
  );
}

