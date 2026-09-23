"use client";

import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { listMissionAssets } from "@/lib/api";
import Layout from "@/components/layout/Layout";
import { Shield, Search, Server, Globe, Wifi } from "lucide-react";

const typeIcons: Record<string, React.ElementType> = {
  host: Server,
  domain: Globe,
  ip_address: Wifi,
};

export default function AssetsPage() {
  const [searchQuery, setSearchQuery] = useState("");
  const [assetTypeFilter, setAssetTypeFilter] = useState<string>("");

  const { data: assets = [], isLoading } = useQuery({
    queryKey: ["assets"],
    queryFn: () => listMissionAssets(""),
  });

  const filteredAssets = assets.filter((a) => {
    const matchesSearch = searchQuery
      ? a.value.toLowerCase().includes(searchQuery.toLowerCase()) ||
        a.label.toLowerCase().includes(searchQuery.toLowerCase())
      : true;
    const matchesType = assetTypeFilter
      ? a.asset_type === assetTypeFilter
      : true;
    return matchesSearch && matchesType;
  });

  return (
    <Layout>
      <div className="p-6 space-y-6">
        <div>
          <h1 className="text-2xl font-bold text-white">Assets</h1>
          <p className="text-sm text-slate-500 mt-1">
            Discovered assets across all missions
          </p>
        </div>

        {/* Filters */}
        <div className="flex items-center gap-3">
          <div className="relative flex-1 max-w-md">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-500" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search assets..."
              className="w-full pl-10 pr-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-emerald-500/50"
            />
          </div>
          <select
            value={assetTypeFilter}
            onChange={(e) => setAssetTypeFilter(e.target.value)}
            className="px-3 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm text-white focus:outline-none focus:ring-2 focus:ring-emerald-500/50"
          >
            <option value="">All Types</option>
            <option value="host">Host</option>
            <option value="domain">Domain</option>
            <option value="ip_address">IP Address</option>
            <option value="web_application">Web Application</option>
            <option value="api">API</option>
          </select>
        </div>

        {isLoading ? (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {[...Array(6)].map((_, i) => (
              <div key={i} className="h-32 bg-slate-800 rounded-xl animate-pulse" />
            ))}
          </div>
        ) : filteredAssets.length === 0 ? (
          <div className="text-center py-12">
            <Shield className="h-12 w-12 text-slate-700 mx-auto mb-4" />
            <p className="text-slate-500 text-sm">
              {searchQuery ? "No assets match your search" : "No assets discovered yet. Run a mission to discover assets."}
            </p>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {filteredAssets.map((asset) => {
              const Icon = typeIcons[asset.asset_type] || Shield;
              const severityColor =
                asset.criticality === "critical"
                  ? "text-red-400"
                  : asset.criticality === "high"
                  ? "text-orange-400"
                  : asset.criticality === "medium"
                  ? "text-yellow-400"
                  : "text-slate-400";

              return (
                <div
                  key={asset.id}
                  className="bg-slate-900 border border-slate-800 rounded-xl p-4 hover:border-slate-700 transition-colors"
                >
                  <div className="flex items-start justify-between mb-3">
                    <div className={`p-2 rounded-lg bg-slate-800`}>
                      <Icon className="h-5 w-5 text-slate-400" />
                    </div>
                    <span className={`text-xs font-medium ${severityColor}`}>
                      {asset.criticality}
                    </span>
                  </div>
                  <h3 className="text-sm font-semibold text-white truncate">
                    {asset.label || asset.value}
                  </h3>
                  <p className="text-xs text-slate-500 mt-1">{asset.value}</p>
                  <div className="flex flex-wrap gap-1.5 mt-3">
                    {asset.open_ports.slice(0, 5).map((port) => (
                      <span
                        key={port}
                        className="px-1.5 py-0.5 bg-slate-800 text-slate-400 rounded text-xs"
                      >
                        {port}
                      </span>
                    ))}
                    {asset.open_ports.length > 5 && (
                      <span className="px-1.5 py-0.5 text-slate-500 rounded text-xs">
                        +{asset.open_ports.length - 5}
                      </span>
                    )}
                  </div>
                  <div className="flex items-center gap-2 mt-2 text-xs text-slate-500">
                    <span>{asset.asset_type.replace(/_/g, " ")}</span>
                    {asset.services.length > 0 && (
                      <>
                        <span>·</span>
                        <span>{asset.services.slice(0, 2).join(", ")}</span>
                      </>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </Layout>
  );
}

