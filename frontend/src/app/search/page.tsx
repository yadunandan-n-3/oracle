"use client";

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useSearchParams } from "next/navigation";
import { useRouter } from "next/navigation";
import { search } from "@/lib/api";
import Layout from "@/components/layout/Layout";
import { Search, Crosshair, Shield, FileSearch, Bug, AlertTriangle } from "lucide-react";

export default function SearchPage() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const initialQuery = searchParams.get("q") || "";
  const [query, setQuery] = useState(initialQuery);
  const { data, isLoading: loading } = useQuery({
    queryKey: ["search", initialQuery],
    queryFn: () => search(initialQuery.trim()),
    enabled: Boolean(initialQuery.trim()),
  });

  const results: Record<string, unknown[]> = {
    missions: Array.isArray(data?.results?.missions) ? data.results.missions : [],
    assets: Array.isArray(data?.results?.assets) ? data.results.assets : [],
    findings: Array.isArray(data?.results?.findings) ? data.results.findings : [],
    cves: Array.isArray(data?.results?.cves) ? data.results.cves : [],
    mitre: Array.isArray(data?.results?.mitre) ? data.results.mitre : [],
  };
  const totalResults = typeof data?.total_results === "number" ? data.total_results : 0;

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (query.trim()) {
      router.push(`/search?q=${encodeURIComponent(query.trim())}`);
    }
  };

  const categoryIcons: Record<string, React.ElementType> = {
    missions: Crosshair,
    assets: Shield,
    findings: FileSearch,
    cves: Bug,
    mitre: AlertTriangle,
  };

  const categoryColors: Record<string, string> = {
    missions: "text-blue-400",
    assets: "text-emerald-400",
    findings: "text-red-400",
    cves: "text-orange-400",
    mitre: "text-cyan-400",
  };

  return (
    <Layout>
      <div className="p-6 space-y-6">
        <div>
          <h1 className="text-2xl font-bold text-white">Search</h1>
          <p className="text-sm text-slate-500 mt-1">
            Search across missions, assets, findings, CVEs, and MITRE techniques
          </p>
        </div>

        {/* Search Bar */}
        <form onSubmit={handleSubmit} className="relative">
          <Search className="absolute left-4 top-1/2 -translate-y-1/2 h-5 w-5 text-slate-500" />
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search across all ORACLE data..."
            className="w-full pl-12 pr-4 py-3 bg-slate-900 border border-slate-700 rounded-xl text-base text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-emerald-500/50 focus:border-emerald-500"
          />
        </form>

        {loading ? (
          <div className="space-y-4">
            {[...Array(3)].map((_, i) => (
              <div key={i} className="h-24 bg-slate-800 rounded-xl animate-pulse" />
            ))}
          </div>
        ) : totalResults > 0 ? (
          <div>
            <p className="text-sm text-slate-500 mb-4">
              {totalResults} result{totalResults !== 1 ? "s" : ""} for &ldquo;
              {initialQuery}&rdquo;
            </p>

            <div className="space-y-6">
              {(Object.entries(results) as [string, unknown[]][])
                .map(([category, items]) => [category, Array.isArray(items) ? items : []] as [string, unknown[]])
                .filter(([, items]) => items.length > 0)
                .map(([category, items]) => (
                    <div key={category}>
                      <div className="flex items-center gap-2 mb-3">
                        {(() => {
                          const Icon = categoryIcons[category] || Search;
                          return (
                            <Icon
                              className={`h-4 w-4 ${
                                categoryColors[category] || "text-slate-400"
                              }`}
                            />
                          );
                        })()}
                        <h2 className="text-sm font-semibold text-white capitalize">
                          {category.replace(/_/g, " ")} ({items.length})
                        </h2>
                      </div>
                      <div className="space-y-2">
                        {(items ?? []).map((item, idx) => {
                          const record = item as Record<string, unknown>;
                          return (
                            <div
                              key={idx}
                              className="bg-slate-900 border border-slate-800 rounded-xl p-4 hover:border-slate-700 transition-colors cursor-pointer"
                              onClick={() => {
                                const id = record.id as string | undefined;
                                if (id && category !== "cves" && category !== "mitre") {
                                  router.push(`/${category}/${id}`);
                                }
                              }}
                            >
                              <div className="flex items-center justify-between">
                                <div className="min-w-0 flex-1">
                                  <p className="text-sm font-medium text-white truncate">
                                    {String(record.title ?? record.name ?? record.value ?? record.id ?? "")}
                                  </p>
                                  <p className="text-xs text-slate-500 mt-0.5">
                                    {record.description
                                      ? String(record.description).slice(0, 100)
                                      : record.asset_value
                                      ? String(record.asset_value)
                                      : record.label
                                      ? String(record.label)
                                      : ""}
                                  </p>
                                </div>
                                {((record.severity !== undefined && record.severity !== null) || (record.status !== undefined && record.status !== null)) && (
                                  <div className="flex items-center gap-2 flex-shrink-0 ml-4">
                                    {record.severity !== undefined && record.severity !== null && (
                                      <span className="px-2 py-0.5 rounded text-xs font-medium uppercase badge-critical">
                                        {String(record.severity)}
                                      </span>
                                    )}
                                    {record.status !== undefined && record.status !== null && (
                                      <span className="text-xs text-slate-500">
                                        {String(record.status).replace(/_/g, " ")}
                                      </span>
                                    )}
                                  </div>
                                )}
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  )
              )}
            </div>
          </div>
        ) : initialQuery ? (
          <div className="text-center py-12">
            <Search className="h-12 w-12 text-slate-700 mx-auto mb-4" />
            <p className="text-slate-500 text-sm">
              No results found for &ldquo;{initialQuery}&rdquo;
            </p>
          </div>
        ) : (
          <div className="text-center py-12">
            <Search className="h-12 w-12 text-slate-700 mx-auto mb-4" />
            <p className="text-slate-500 text-sm">
              Enter a search query to find assets, findings, CVEs, missions, and
              more
            </p>
          </div>
        )}
      </div>
    </Layout>
  );
}
