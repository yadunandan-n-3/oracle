"use client";

import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { useRouter } from "next/navigation";
import { listMissions, createMission, executeMission, cancelMission } from "@/lib/api";
import Layout from "@/components/layout/Layout";
import {
  Crosshair,
  Plus,
  Play,
  XCircle,
  RefreshCw,
  Search,
} from "lucide-react";

const statusColors: Record<string, string> = {
  completed: "badge-completed",
  in_progress: "badge-active",
  failed: "badge-failed",
  draft: "badge-pending",
  planning: "badge-pending",
  cancelled: "text-slate-400 bg-slate-500/10 border-slate-500/20",
};

export default function MissionsPage() {
  const router = useRouter();
  const [showCreate, setShowCreate] = useState(false);
  const [statusFilter, setStatusFilter] = useState<string>("");
  const [searchQuery, setSearchQuery] = useState("");

  const { data, isLoading, refetch } = useQuery({
    queryKey: ["missions", statusFilter],
    queryFn: () => listMissions(statusFilter ? { status: statusFilter } : {}),
  });

  const missions = data || [];

  const filteredMissions = missions.filter((m) =>
    searchQuery
      ? m.name.toLowerCase().includes(searchQuery.toLowerCase())
      : true
  );

  return (
    <Layout>
      <div className="p-6 space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-white">Missions</h1>
            <p className="text-sm text-slate-500 mt-1">
              Manage and execute security assessment missions
            </p>
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={() => refetch()}
              className="p-2 text-slate-400 hover:text-white hover:bg-slate-800 rounded-lg transition-colors"
            >
              <RefreshCw className="h-4 w-4" />
            </button>
            <button
              onClick={() => setShowCreate(!showCreate)}
              className="flex items-center gap-2 px-4 py-2 bg-emerald-500 hover:bg-emerald-600 text-white text-sm font-medium rounded-lg transition-colors"
            >
              <Plus className="h-4 w-4" />
              New Mission
            </button>
          </div>
        </div>

        {/* Quick Filters */}
        <div className="flex items-center gap-2">
          {["", "in_progress", "completed", "failed", "draft"].map(
            (status) => (
              <button
                key={status}
                onClick={() => setStatusFilter(status)}
                className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                  statusFilter === status
                    ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
                    : "text-slate-400 bg-slate-800 border border-slate-700 hover:border-slate-600"
                }`}
              >
                {status ? status.replace(/_/g, " ") : "All"}
              </button>
            )
          )}
        </div>

        {/* Search */}
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-500" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search missions..."
            className="w-full pl-10 pr-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-emerald-500/50"
          />
        </div>

        {/* Create Mission Form */}
        {showCreate && (
          <CreateMissionForm
            onClose={() => setShowCreate(false)}
            onCreated={() => {
              setShowCreate(false);
              refetch();
            }}
          />
        )}

        {/* Loading */}
        {isLoading ? (
          <div className="space-y-3">
            {[...Array(3)].map((_, i) => (
              <div
                key={i}
                className="h-24 bg-slate-800 rounded-xl animate-pulse"
              />
            ))}
          </div>
        ) : filteredMissions.length === 0 ? (
          <div className="text-center py-12">
            <Crosshair className="h-12 w-12 text-slate-700 mx-auto mb-4" />
            <p className="text-slate-500 text-sm">
              {searchQuery
                ? "No missions match your search"
                : "No missions yet. Create your first mission to get started."}
            </p>
          </div>
        ) : (
          <div className="space-y-3">
            {filteredMissions.map((mission) => (
              <div
                key={mission.id}
                className="bg-slate-900 border border-slate-800 rounded-xl p-5 hover:border-slate-700 transition-colors"
              >
                <div className="flex items-start justify-between">
                  <div
                    className="cursor-pointer flex-1"
                    onClick={() => router.push(`/missions/${mission.id}`)}
                  >
                    <div className="flex items-center gap-3">
                      <h3 className="text-base font-semibold text-white">
                        {mission.name}
                      </h3>
                      <span
                        className={`px-2 py-0.5 rounded text-xs font-medium ${
                          statusColors[mission.status] || "text-slate-400 bg-slate-500/10"
                        }`}
                      >
                        {mission.status.replace(/_/g, " ")}
                      </span>
                    </div>
                    <p className="text-xs text-slate-500 mt-2">
                      {mission.mission_type.replace(/_/g, " ")}
                      {mission.total_findings > 0 &&
                        ` · ${mission.total_findings} findings`}
                      {mission.total_assets > 0 &&
                        ` · ${mission.total_assets} assets`}
                      {mission.created_at &&
                        ` · ${new Date(mission.created_at).toLocaleDateString()}`}
                    </p>
                  </div>

                  <div className="flex items-center gap-2">
                    {(mission.status === "draft" ||
                      mission.status === "failed" ||
                      mission.status === "completed") && (
                      <button
                        onClick={async () => {
                          await executeMission(mission.id);
                          refetch();
                        }}
                        className="flex items-center gap-1.5 px-3 py-1.5 bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 rounded-lg text-xs font-medium hover:bg-emerald-500/20 transition-colors"
                      >
                        <Play className="h-3 w-3" />
                        Execute
                      </button>
                    )}
                    {mission.status === "in_progress" && (
                      <button
                        onClick={async () => {
                          await cancelMission(mission.id);
                          refetch();
                        }}
                        className="flex items-center gap-1.5 px-3 py-1.5 bg-red-500/10 text-red-400 border border-red-500/20 rounded-lg text-xs font-medium hover:bg-red-500/20 transition-colors"
                      >
                        <XCircle className="h-3 w-3" />
                        Cancel
                      </button>
                    )}
                    <button
                      onClick={() => router.push(`/missions/${mission.id}`)}
                      className="px-3 py-1.5 text-slate-400 hover:text-white text-xs transition-colors"
                    >
                      View
                    </button>
                  </div>
                </div>

                {(mission.critical_findings > 0 || mission.high_findings > 0) && (
                  <div className="flex items-center gap-3 mt-3 text-xs">
                    {mission.critical_findings > 0 && (
                      <span className="text-red-400">
                        {mission.critical_findings} critical
                      </span>
                    )}
                    {mission.high_findings > 0 && (
                      <span className="text-orange-400">
                        {mission.high_findings} high
                      </span>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </Layout>
  );
}

function CreateMissionForm({
  onClose,
  onCreated,
}: {
  onClose: () => void;
  onCreated: () => void;
}) {
  const router = useRouter();
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [missionType, setMissionType] = useState("external_attack_surface");
  const [targetDomains, setTargetDomains] = useState("");
  const [targetUrls, setTargetUrls] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) return;
    setLoading(true);
    try {
      const mission = await createMission({
        name: name.trim(),
        description: description.trim(),
        mission_type: missionType,
        target_domains: targetDomains
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean),
        target_urls: targetUrls
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean),
      });
      router.push(`/missions/${mission.id}`);
      onCreated();
    } catch (error) {
      console.error("Failed to create mission:", error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <form
      onSubmit={handleSubmit}
      className="bg-slate-900 border border-slate-700 rounded-xl p-5 space-y-4"
    >
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold text-white">Create New Mission</h3>
        <button
          type="button"
          onClick={onClose}
          className="text-slate-400 hover:text-white transition-colors"
        >
          <XCircle className="h-4 w-4" />
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="space-y-1.5">
          <label className="text-xs font-medium text-slate-400">Name</label>
          <input
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g., External Attack Surface Assessment"
            className="w-full px-3 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-emerald-500/50"
            required
          />
        </div>

        <div className="space-y-1.5">
          <label className="text-xs font-medium text-slate-400">Type</label>
          <select
            value={missionType}
            onChange={(e) => setMissionType(e.target.value)}
            className="w-full px-3 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm text-white focus:outline-none focus:ring-2 focus:ring-emerald-500/50"
          >
            <option value="external_attack_surface">
              External Attack Surface
            </option>
            <option value="api_security_assessment">
              API Security Assessment
            </option>
            <option value="web_application_scan">Web Application Scan</option>
            <option value="cloud_audit">Cloud Audit</option>
            <option value="incident_investigation">
              Incident Investigation
            </option>
            <option value="custom">Custom</option>
          </select>
        </div>

        <div className="space-y-1.5">
          <label className="text-xs font-medium text-slate-400">
            Target Domains (comma-separated)
          </label>
          <input
            type="text"
            value={targetDomains}
            onChange={(e) => setTargetDomains(e.target.value)}
            placeholder="e.g., example.com, api.example.com"
            className="w-full px-3 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-emerald-500/50"
          />
        </div>

        <div className="space-y-1.5">
          <label className="text-xs font-medium text-slate-400">
            Target URLs (comma-separated)
          </label>
          <input
            type="text"
            value={targetUrls}
            onChange={(e) => setTargetUrls(e.target.value)}
            placeholder="e.g., https://example.com"
            className="w-full px-3 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-emerald-500/50"
          />
        </div>
      </div>

      <div className="space-y-1.5">
        <label className="text-xs font-medium text-slate-400">
          Description (optional)
        </label>
        <textarea
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          placeholder="Describe the mission objectives..."
          rows={2}
          className="w-full px-3 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-emerald-500/50 resize-none"
        />
      </div>

      <div className="flex justify-end gap-3 pt-2">
        <button
          type="button"
          onClick={onClose}
          className="px-4 py-2 text-sm text-slate-400 hover:text-white transition-colors"
        >
          Cancel
        </button>
        <button
          type="submit"
          disabled={loading || !name.trim()}
          className="px-4 py-2 bg-emerald-500 hover:bg-emerald-600 disabled:bg-emerald-500/50 text-white text-sm font-medium rounded-lg transition-colors flex items-center gap-2"
        >
          {loading ? "Creating..." : "Create Mission"}
        </button>
      </div>
    </form>
  );
}
