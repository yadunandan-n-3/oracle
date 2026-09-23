"use client";

import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { useRouter } from "next/navigation";
import { listReports } from "@/lib/api";
import Layout from "@/components/layout/Layout";
import { FileText, Search, RefreshCw, Download } from "lucide-react";

export default function ReportsPage() {
  const router = useRouter();
  const [searchQuery, setSearchQuery] = useState("");

  const { data, isLoading, refetch } = useQuery({
    queryKey: ["reports"],
    queryFn: () => listReports({ limit: 50 }),
  });

  const reports = data?.reports || [];

  const filtered = reports.filter((r) =>
    searchQuery
      ? r.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
        r.mission_name.toLowerCase().includes(searchQuery.toLowerCase())
      : true
  );

  return (
    <Layout>
      <div className="p-6 space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-white">Reports</h1>
            <p className="text-sm text-slate-500 mt-1">
              {data?.total || 0} reports · Security assessment reports
            </p>
          </div>
          <button
            onClick={() => refetch()}
            className="p-2 text-slate-400 hover:text-white hover:bg-slate-800 rounded-lg transition-colors"
          >
            <RefreshCw className="h-4 w-4" />
          </button>
        </div>

        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-500" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search reports..."
            className="w-full pl-10 pr-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-emerald-500/50"
          />
        </div>

        {isLoading ? (
          <div className="space-y-3">
            {[...Array(3)].map((_, i) => (
              <div key={i} className="h-28 bg-slate-800 rounded-xl animate-pulse" />
            ))}
          </div>
        ) : filtered.length === 0 ? (
          <div className="text-center py-12">
            <FileText className="h-12 w-12 text-slate-700 mx-auto mb-4" />
            <p className="text-slate-500 text-sm">
              {searchQuery
                ? "No reports match your search"
                : "No reports yet. Reports are generated after missions complete."}
            </p>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {filtered.map((report) => (
              <div
                key={report.id}
                className="bg-slate-900 border border-slate-800 rounded-xl p-5 hover:border-slate-700 transition-colors"
              >
                <div className="flex items-start justify-between mb-3">
                  <div className="min-w-0 flex-1">
                    <h3
                      className="text-sm font-semibold text-white truncate cursor-pointer hover:text-emerald-400"
                      onClick={() => router.push(`/reports/${report.id}`)}
                    >
                      {report.title}
                    </h3>
                    <p className="text-xs text-slate-500 mt-1">
                      {report.report_type.replace(/_/g, " ")}
                    </p>
                  </div>
                  <span
                    className={`px-2 py-0.5 rounded text-xs font-medium ${
                      report.status === "completed"
                        ? "badge-completed"
                        : report.status === "failed"
                        ? "badge-failed"
                        : "badge-pending"
                    }`}
                  >
                    {report.status}
                  </span>
                </div>

                <div className="flex items-center gap-4 text-xs text-slate-500 mb-3">
                  <span>Mission: {report.mission_name}</span>
                  {report.generated_at && (
                    <span>
                      {new Date(report.generated_at).toLocaleDateString()}
                    </span>
                  )}
                </div>

                <div className="flex items-center gap-3 text-xs">
                  <span className="text-slate-500">
                    {report.critical_findings > 0 && (
                      <span className="text-red-400 mr-2">
                        {report.critical_findings} critical
                      </span>
                    )}
                    {report.high_findings > 0 && (
                      <span className="text-orange-400 mr-2">
                        {report.high_findings} high
                      </span>
                    )}
                    {report.total_findings} findings
                  </span>
                </div>

                <div className="flex items-center gap-2 mt-4 pt-3 border-t border-slate-800">
                  <button
                    onClick={() => router.push(`/reports/${report.id}`)}
                    className="flex items-center gap-1.5 px-3 py-1.5 bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 rounded-lg text-xs font-medium hover:bg-emerald-500/20 transition-colors"
                  >
                    <Download className="h-3 w-3" />
                    View Report
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </Layout>
  );
}
