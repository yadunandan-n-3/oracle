"use client";

import { useQuery } from "@tanstack/react-query";
import { ArrowLeft, ShieldAlert } from "lucide-react";
import { useParams, useRouter } from "next/navigation";
import Layout from "@/components/layout/Layout";
import { getFinding } from "@/lib/api";

export default function FindingDetailPage() {
  const params = useParams<{ id: string }>();
  const router = useRouter();
  const { data: finding, isLoading } = useQuery({
    queryKey: ["finding", params.id],
    queryFn: () => getFinding(params.id),
  });

  if (isLoading || !finding) {
    return <Layout><div className="p-6 text-sm text-slate-400">Loading finding…</div></Layout>;
  }

  const intelligence = finding.threat_intelligence || {};
  return (
    <Layout>
      <div className="p-6 space-y-6">
        <button onClick={() => router.back()} className="flex items-center gap-2 text-sm text-slate-400 hover:text-white">
          <ArrowLeft className="h-4 w-4" /> Back to findings
        </button>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
          <div className="flex items-start justify-between gap-4">
            <div>
              <p className="text-xs uppercase tracking-wide text-slate-500">{finding.severity} · {finding.status}</p>
              <h1 className="text-2xl font-bold text-white mt-1">{finding.title}</h1>
              <p className="text-sm text-slate-400 mt-2">{finding.description}</p>
            </div>
            <div className="text-right shrink-0">
              <p className="text-3xl font-bold text-white">{finding.risk_score?.toFixed(1) ?? "—"}</p>
              <p className="text-xs uppercase text-slate-500">{finding.risk_level} risk / 100</p>
            </div>
          </div>
        </div>

        <div className="grid gap-4 lg:grid-cols-2">
          <section className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
            <h2 className="font-semibold text-white flex items-center gap-2"><ShieldAlert className="h-4 w-4" /> Threat intelligence</h2>
            <p className="text-xs text-slate-500">Status: {finding.intelligence_status}</p>
            <dl className="grid grid-cols-2 gap-3 text-sm">
              <div><dt className="text-slate-500">CVE</dt><dd className="text-slate-200">{intelligence.cve?.cve_id || finding.cve_id || "Unavailable"}</dd></div>
              <div><dt className="text-slate-500">CWE</dt><dd className="text-slate-200">{intelligence.cwe?.cwe_id || finding.cwe_id || "Unavailable"}</dd></div>
              <div><dt className="text-slate-500">OWASP</dt><dd className="text-slate-200">{intelligence.owasp?.owasp_id || "Unavailable"}</dd></div>
              <div><dt className="text-slate-500">EPSS</dt><dd className="text-slate-200">{intelligence.epss ? `${(intelligence.epss.epss_score * 100).toFixed(1)}%` : "Unavailable"}</dd></div>
              <div><dt className="text-slate-500">CISA KEV</dt><dd className="text-slate-200">{intelligence.kev ? "Listed" : "Not listed / unavailable"}</dd></div>
              <div><dt className="text-slate-500">CVSS</dt><dd className="text-slate-200">{finding.cvss_score ?? "Unavailable"}</dd></div>
            </dl>
          </section>

          <section className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
            <h2 className="font-semibold text-white">Risk explanation</h2>
            <p className="text-sm text-slate-300">{finding.risk_explanation?.summary || "No risk explanation available."}</p>
            <div className="space-y-2">
              {finding.risk_factors.map((factor) => (
                <div key={factor.name} className="border-t border-slate-800 pt-2 text-xs">
                  <div className="flex justify-between text-slate-300"><span>{factor.name.replaceAll("_", " ")}</span><span>{(factor.value * factor.weight * 100).toFixed(1)} pts</span></div>
                  <p className="text-slate-500 mt-1">{factor.evidence} · {factor.source}</p>
                </div>
              ))}
            </div>
          </section>
        </div>

        <section className="bg-slate-900 border border-slate-800 rounded-xl p-5">
          <h2 className="font-semibold text-white">Provenance</h2>
          <p className="text-sm text-slate-400 mt-2">Asset: {finding.asset_value}</p>
          <p className="text-sm text-slate-400">Supporting evidence: {finding.evidence_ids.length}</p>
          <p className="text-xs text-slate-600 mt-2">Calculated by {finding.risk_calculation_metadata.calculated_by || "unavailable"}</p>
        </section>
      </div>
    </Layout>
  );
}
