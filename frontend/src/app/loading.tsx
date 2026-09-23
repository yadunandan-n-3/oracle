export default function Loading() {
  return (
    <div className="flex min-h-screen items-center justify-center bg-slate-950 text-slate-400">
      <div className="flex items-center gap-3 rounded-full border border-slate-800 bg-slate-900/80 px-4 py-2">
        <div className="h-2.5 w-2.5 animate-pulse rounded-full bg-emerald-400" />
        <span className="text-sm">Loading ORACLE workspace…</span>
      </div>
    </div>
  );
}
