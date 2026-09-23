"use client";

import { useState } from "react";
import { useParams, useRouter } from "next/navigation";
import { useQuery } from "@tanstack/react-query";
import { getMission, executeMission, cancelMission } from "@/lib/api";
import Layout from "@/components/layout/Layout";
import { ArrowLeft, Play, XCircle, RefreshCw } from "lucide-react";

export default function MissionDetailPage() {
  const params = useParams();
  const router = useRouter();
  const missionId = params?.id as string | undefined;
  const [loadingAction, setLoadingAction] = useState(false);
  const [executeError, setExecuteError] = useState("");

  const { data: mission, isLoading, error, refetch } = useQuery({
    queryKey: ["mission", missionId],
    queryFn: () => getMission(String(missionId)),
    enabled: !!missionId,
  });

  const canExecute =
    mission &&
    ["draft", "pending", "paused"].includes(mission.status);

  const handleExecute = async () => {
    if (!missionId) return;
    setLoadingAction(true);
    setExecuteError("");
    try {
      await executeMission(missionId);
      await refetch();
    } catch (err) {
      const message =
        err instanceof Error ? err.message : "Failed to execute mission.";
      setExecuteError(message);
      console.error(err);
    } finally {
      setLoadingAction(false);
    }
  };

  const handleCancel = async () => {
    if (!missionId) return;
    setLoadingAction(true);
    try {
      await cancelMission(missionId);
      await refetch();
    } catch (err) {
      console.error(err);
    } finally {
      setLoadingAction(false);
    }
  };

  return (
    <Layout>
      <div className="p-6 space-y-6">
        <button
          type="button"
          onClick={() => router.push("/missions")}
          className="inline-flex items-center gap-2 text-slate-400 hover:text-white text-sm"
        >
          <ArrowLeft className="h-4 w-4" />
          Back to missions
        </button>

        {isLoading ? (
          <div className="h-40 rounded-3xl bg-slate-900 border border-slate-800 animate-pulse" />
        ) : error ? (
          <div className="rounded-3xl bg-slate-900 border border-red-500 p-6 text-red-300">
            <p className="font-semibold">Unable to load mission</p>
            <p className="text-sm text-slate-400">Please refresh or try again later.</p>
          </div>
        ) : !mission ? (
          <div className="rounded-3xl bg-slate-900 border border-slate-800 p-6 text-slate-400">
            Mission not found.
          </div>
        ) : (
          <div className="space-y-6">
            <div className="rounded-3xl bg-slate-900 border border-slate-800 p-6">
              <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
                <div>
                  <p className="text-xs uppercase tracking-[0.24em] text-slate-500 mb-2">
                    Mission details
                  </p>
                  <h1 className="text-3xl font-semibold text-white">{mission.name}</h1>
                  <p className="mt-3 text-sm text-slate-400 max-w-3xl">
                    {mission.description || "No description provided."}
                  </p>
                </div>
                <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
                  <DetailBadge label="Status" value={mission.status.replace(/_/g, " ")} />
                  <DetailBadge label="Type" value={mission.mission_type.replace(/_/g, " ")} />
                  <DetailBadge label="Priority" value={mission.priority} />
                </div>
              </div>

              <div className="mt-6 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
                <Metric label="Assets" value={mission.total_assets ?? 0} />
                <Metric label="Findings" value={mission.total_findings ?? 0} />
                <Metric label="Critical" value={mission.critical_findings ?? 0} />
                <Metric label="High" value={mission.high_findings ?? 0} />
              </div>

              <div className="mt-6 flex flex-wrap gap-3">
                {canExecute && (
                  <button
                    type="button"
                    onClick={handleExecute}
                    disabled={loadingAction}
                    className="inline-flex items-center gap-2 rounded-xl bg-emerald-500 px-4 py-2 text-sm font-medium text-white transition hover:bg-emerald-600 disabled:cursor-not-allowed disabled:opacity-60"
                  >
                    <Play className="h-4 w-4" />
                    Execute
                  </button>
                )}
                {mission?.status === "in_progress" && (
                  <button
                    type="button"
                    onClick={handleCancel}
                    disabled={loadingAction}
                    className="inline-flex items-center gap-2 rounded-xl bg-red-500 px-4 py-2 text-sm font-medium text-white transition hover:bg-red-600 disabled:cursor-not-allowed disabled:opacity-60"
                  >
                    <XCircle className="h-4 w-4" />
                    Cancel
                  </button>
                )}
                <button
                  type="button"
                  onClick={() => refetch()}
                  disabled={loadingAction}
                  className="inline-flex items-center gap-2 rounded-xl border border-slate-700 bg-slate-950 px-4 py-2 text-sm font-medium text-slate-300 transition hover:border-slate-600 hover:bg-slate-900 disabled:cursor-not-allowed disabled:opacity-60"
                >
                  <RefreshCw className="h-4 w-4" />
                  Refresh
                </button>
              </div>
              {executeError ? (
                <div className="mt-4 rounded-2xl border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-200">
                  {executeError}
                </div>
              ) : mission && !canExecute && mission.status !== "in_progress" ? (
                <div className="mt-4 rounded-2xl border border-slate-700 bg-slate-950 px-4 py-3 text-sm text-slate-400">
                  Execution is not available while mission status is &quot;{mission.status}&quot;.
                </div>
              ) : null}
            </div>

            <div className="grid gap-6 xl:grid-cols-3">
              <DetailCard title="Mission timeline">
                <DataRow label="Created" value={formatDate(mission.created_at)} />
                <DataRow label="Started" value={mission.started_at ? formatDate(mission.started_at) : "—"} />
                <DataRow label="Completed" value={mission.completed_at ? formatDate(mission.completed_at) : "—"} />
                <DataRow label="Progress" value={`${mission.progress_percentage ?? 0}%`} />
              </DetailCard>

              <DetailCard title="Target">
                <ListField label="Domains" items={mission.target_domains} />
                <ListField label="URLs" items={mission.target_urls} />
                <ListField label="IP ranges" items={mission.target_ip_ranges} />
              </DetailCard>

              <DetailCard title="Goals">
                <ListField label="Goals" items={mission.goals} emptyText="No goals yet." />
              </DetailCard>
            </div>
          </div>
        )}
      </div>
    </Layout>
  );
}

function DetailBadge({
  label,
  value,
}: {
  label: string;
  value: string | number;
}) {
  return (
    <div className="rounded-3xl border border-slate-800 bg-slate-950 px-4 py-3 text-center">
      <p className="text-xs text-slate-500 uppercase tracking-[0.2em]">{label}</p>
      <p className="mt-2 text-sm font-semibold text-white truncate">{value}</p>
    </div>
  );
}

function Metric({
  label,
  value,
}: {
  label: string;
  value: number;
}) {
  return (
    <div className="rounded-3xl border border-slate-800 bg-slate-950 px-4 py-5">
      <p className="text-sm text-slate-400">{label}</p>
      <p className="mt-2 text-2xl font-semibold text-white">{value}</p>
    </div>
  );
}

function DetailCard({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <div className="rounded-3xl border border-slate-800 bg-slate-900 p-5">
      <h2 className="text-sm font-semibold text-white mb-4">{title}</h2>
      <div className="space-y-3 text-sm text-slate-400">{children}</div>
    </div>
  );
}

function DataRow({
  label,
  value,
}: {
  label: string;
  value: string;
}) {
  return (
    <div className="flex items-center justify-between gap-4">
      <span className="text-slate-500">{label}</span>
      <span className="text-slate-200">{value}</span>
    </div>
  );
}

function ListField({
  label,
  items = [],
  emptyText = "None",
}: {
  label: string;
  items?: string[];
  emptyText?: string;
}) {
  return (
    <div>
      <p className="text-slate-500 text-xs uppercase tracking-[0.16em] mb-2">{label}</p>
      {items.length > 0 ? (
        <ul className="space-y-2 text-sm text-slate-300">
          {items.map((item) => (
            <li key={item} className="rounded-xl bg-slate-950 px-3 py-2">
              {item}
            </li>
          ))}
        </ul>
      ) : (
        <p className="text-sm text-slate-500">{emptyText}</p>
      )}
    </div>
  );
}

function formatDate(value: string) {
  try {
    return new Date(value).toLocaleString();
  } catch {
    return value;
  }
}
