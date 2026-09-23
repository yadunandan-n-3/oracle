"use client";

import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { listMissions, getMissionGraph } from "@/lib/api";
import Layout from "@/components/layout/Layout";
import { Share2, Search } from "lucide-react";

const nodeColors: Record<string, string> = {
  mission: "text-emerald-400",
  asset: "text-blue-400",
  port: "text-yellow-400",
  service: "text-purple-400",
  finding: "text-red-400",
  cve: "text-orange-400",
  mitre_technique: "text-cyan-400",
  evidence: "text-slate-400",
};

export default function GraphPage() {
  const [selectedMission, setSelectedMission] = useState<string>("");
  const [searchQuery, setSearchQuery] = useState("");

  const { data: missions } = useQuery({
    queryKey: ["missions"],
    queryFn: () => listMissions({ limit: 50 }),
  });

  const { data: graphData, isLoading } = useQuery({
    queryKey: ["mission-graph", selectedMission],
    queryFn: () => getMissionGraph(selectedMission),
    enabled: !!selectedMission,
  });

  const nodes = graphData?.nodes || [];
  const relationships = graphData?.relationships || [];

  const filteredNodes = searchQuery
    ? nodes.filter(
        (n) =>
          n.label?.toLowerCase().includes(searchQuery.toLowerCase()) ||
          n.id?.toLowerCase().includes(searchQuery.toLowerCase())
      )
    : nodes;

  // Group by type
  const nodesByType: Record<string, typeof nodes> = {};
  for (const node of filteredNodes) {
    const type = node.type || "unknown";
    if (!nodesByType[type]) nodesByType[type] = [];
    nodesByType[type].push(node);
  }

  return (
    <Layout>
      <div className="p-6 space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-white">Knowledge Graph</h1>
            <p className="text-sm text-slate-500 mt-1">
              {graphData?.available === false
                ? "Neo4j not available"
                : `${nodes.length} nodes · ${relationships.length} relationships`}
            </p>
          </div>
        </div>

        {/* Controls */}
        <div className="flex flex-wrap items-center gap-4">
          <select
            value={selectedMission}
            onChange={(e) => setSelectedMission(e.target.value)}
            className="px-3 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm text-white focus:outline-none focus:ring-2 focus:ring-emerald-500/50"
          >
            <option value="">Select a mission...</option>
            {(missions || []).map((m) => (
              <option key={m.id} value={m.id}>
                {m.name}
              </option>
            ))}
          </select>

          <div className="relative flex-1 max-w-xs">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-500" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Filter nodes..."
              className="w-full pl-10 pr-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-emerald-500/50"
            />
          </div>
        </div>

        {/* Graph Visualization */}
        {isLoading ? (
          <div className="h-96 bg-slate-900 border border-slate-800 rounded-xl flex items-center justify-center">
            <div className="text-slate-500 text-sm">Loading graph data...</div>
          </div>
        ) : !selectedMission ? (
          <div className="h-96 bg-slate-900 border border-slate-800 rounded-xl flex items-center justify-center">
            <div className="text-center">
              <Share2 className="h-12 w-12 text-slate-700 mx-auto mb-4" />
              <p className="text-slate-500 text-sm">
                Select a mission to view its knowledge graph
              </p>
            </div>
          </div>
        ) : nodes.length === 0 ? (
          <div className="h-96 bg-slate-900 border border-slate-800 rounded-xl flex items-center justify-center">
            <div className="text-center">
              <Share2 className="h-12 w-12 text-slate-700 mx-auto mb-4" />
              <p className="text-slate-500 text-sm">
                No graph data available for this mission
              </p>
            </div>
          </div>
        ) : (
          <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
            {/* Node list */}
            <div className="lg:col-span-1 bg-slate-900 border border-slate-800 rounded-xl p-4 max-h-[600px] overflow-y-auto">
              <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">
                Nodes ({filteredNodes.length})
              </h3>
              <div className="space-y-3">
                {Object.entries(nodesByType).map(([type, typeNodes]) => (
                  <div key={type}>
                    <h4 className="text-xs font-medium text-slate-500 mb-1.5 capitalize">
                      {type.replace(/_/g, " ")} ({typeNodes.length})
                    </h4>
                    <div className="space-y-1">
                      {typeNodes.slice(0, 20).map((node) => (
                        <div
                          key={node.id}
                          className="flex items-center gap-2 px-2 py-1.5 rounded hover:bg-slate-800 text-xs"
                        >
                          <span
                            className={`w-1.5 h-1.5 rounded-full ${
                              nodeColors[node.type] || "text-slate-500"
                            }`}
                          >
                            ●
                          </span>
                          <span className="text-slate-300 truncate">
                            {node.label || node.id}
                          </span>
                        </div>
                      ))}
                      {typeNodes.length > 20 && (
                        <p className="text-xs text-slate-600 px-2">
                          +{typeNodes.length - 20} more
                        </p>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Graph display */}
            <div className="lg:col-span-3 bg-slate-900 border border-slate-800 rounded-xl p-4">
              <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">
                Graph View
              </h3>
              <div className="space-y-3">
                <p className="text-xs text-slate-500">
                  This graph view shows the relationships between entities in
                  this mission. For a fully interactive graph visualization, the
                  Knowledge Graph API is connected to Neo4j.
                </p>
                <div className="bg-slate-950 rounded-lg p-4 space-y-2 max-h-[500px] overflow-y-auto">
                  {relationships.map((rel, idx) => {
                    const source = nodes.find((n) => n.id === rel.source);
                    const target = nodes.find((n) => n.id === rel.target);
                    return (
                      <div
                        key={idx}
                        className="flex items-center gap-2 text-xs text-slate-400"
                      >
                        <span className="text-blue-400 truncate max-w-[120px]">
                          {source?.label || rel.source}
                        </span>
                        <span className="text-emerald-500 mx-1">
                          ──{rel.type}──
                        </span>
                        <span className="text-orange-400 truncate max-w-[120px]">
                          {target?.label || rel.target}
                        </span>
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </Layout>
  );
}
