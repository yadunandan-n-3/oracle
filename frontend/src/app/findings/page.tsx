"use client";

import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { useRouter } from "next/navigation";
import { listFindings } from "@/lib/api";
import Layout from "@/components/layout/Layout";
import { FileSearch, Search, RefreshCw } from "lucide-react";

const severityColors: Record<string, string> = {
  critical: "badge-critical",
  high: "badge-high",
  medium: "badge-medium",
  low: "badge-low",
  informational: "badge-info",
};

export default function FindingsPage() {
  const router = useRouter();
  const [searchQuery, setSearchQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState<string>("");
  const [statusFilter, setStatusFilter] = useState<string>("");

  const { data, isLoading, refetch } = useQuery({
    queryKey: ["findings", severityFilter, statusFilter],
    queryFn: () =>
      listFindings({
        severity: severityFilter || undefined,
        status: statusFilter || undefined,
        limit: 100,
      }),
    refetchInterval: 10_000,
  });

  const findings = data?.findings || [];

  const filteredFindings = findings.filter((f) => {
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      return (
        f.title.toLowerCase().includes(q) ||
        f.asset_value.toLowerCase().includes(q) ||
        (f.cve_id && f.cve_id.toLowerCase().includes(q))
      );
    }
    return true;
  });

  return (
    <Layout>
      <div className="p-6 space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-white">Findings</h1>
            <p className="text-sm text-slate-500 mt-1">
              {data?.total || 0} total findings · Security vulnerabilities and
              misconfigurations
            </p>
          </div>
          <button
            onClick={() => refetch()}
            className="p-2 text-slate-400 hover:text-white hover:bg-slate-800 rounded-lg transition-colors"
          >
            <RefreshCw className="h-4 w-4" />
          </button>
        </div>

        {/* Filters */}
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-xs text-slate-500 mr-1">Severity:</span>
          {["", "critical", "high", "medium", "low"].map((sev) => (
            <button
              key={sev}
              onClick={() => setSeverityFilter(sev)}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                severityFilter === sev
                  ? sev === "critical"
                    ? "bg-red-500/10 text-red-400 border border-red-500/20"
                    : sev === "high"
                    ? "bg-orange-500/10 text-orange-400 border border-orange-500/20"
                    : sev === "medium"
                    ? "bg-yellow-500/10 text-yellow-400 border border-yellow-500/20"
                    : "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
                  : "text-slate-400 bg-slate-800 border border-slate-700 hover:border-slate-600"
              }`}
            >
              {sev ? sev : "All"}
            </button>
          ))}

          <span className="text-xs text-slate-500 ml-4 mr-1">Status:</span>
          {["", "open", "in_progress", "resolved"].map((st) => (
            <button
              key={st}
              onClick={() => setStatusFilter(st)}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                statusFilter === st
                  ? "bg-blue-500/10 text-blue-400 border border-blue-500/20"
                  : "text-slate-400 bg-slate-800 border border-slate-700 hover:border-slate-600"
              }`}
            >
              {st ? st.replace(/_/g, " ") : "All"}
            </button>
          ))}
        </div>

        {/* Search */}
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-500" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search by title, asset, or CVE..."
            className="w-full pl-10 pr-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-emerald-500/50"
          />
        </div>

        {/* Content */}
        {isLoading ? (
          <div className="space-y-3">
            {[...Array(5)].map((_, i) => (
              <div key={i} className="h-20 bg-slate-800 rounded-xl animate-pulse" />
            ))}
          </div>
        ) : filteredFindings.length === 0 ? (
          <div className="text-center py-12">
            <FileSearch className="h-12 w-12 text-slate-700 mx-auto mb-4" />
            <p className="text-slate-500 text-sm">
              {searchQuery
                ? "No findings match your search"
                : "No findings yet. Findings appear after missions are executed."}
            </p>
          </div>
        ) : (
          <div className="space-y-2">
            {filteredFindings.map((finding) => (
              <div
                key={finding.id}
                onClick={() => router.push(`/findings/${finding.id}`)}
                className="bg-slate-900 border border-slate-800 rounded-xl p-4 hover:border-slate-700 transition-colors cursor-pointer"
              >
                <div className="flex items-start justify-between">
                  <div className="flex items-center gap-3 min-w-0 flex-1">
                    <span
                      className={`px-2 py-0.5 rounded text-xs font-medium flex-shrink-0 ${
                        severityColors[finding.severity] || "badge-info"
                      }`}
                    >
                      {finding.severity}
                    </span>
                    <div className="min-w-0">
                      <p className="text-sm font-medium text-white truncate">
                        {finding.title}
                      </p>
                      <p className="text-xs text-slate-500 mt-0.5 truncate">
                        {finding.asset_value}
                        {finding.cve_id && (
                          <span className="ml-2 text-red-400 font-mono">
                            {finding.cve_id}
                          </span>
                        )}
                        <span className="ml-2">
                          {finding.status.replace(/_/g, " ")}
                        </span>
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-3 flex-shrink-0 ml-4">
                    {finding.risk_score !== null && (
                      <span className="text-xs font-medium text-slate-400">
                        Risk: {finding.risk_score.toFixed(1)}
                      </span>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </Layout>
  );
}

