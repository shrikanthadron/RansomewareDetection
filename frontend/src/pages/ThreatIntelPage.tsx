import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { Info, Radar } from "lucide-react";
import { api, getApiErrorMessage } from "@/lib/api";
import { formatDateTime } from "@/lib/utils";
import {
  Card,
  EmptyState,
  ErrorBanner,
  LoadingState,
  RiskBadge,
  VerdictBadge,
} from "@/components/ui/primitives";

export function ThreatIntelPage() {
  const navigate = useNavigate();
  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["threat-intel"],
    queryFn: async () => (await api.get("/api/threats/overview")).data,
  });

  if (isLoading) return <LoadingState message="Aggregating internal threat intelligence..." />;
  if (error) return <ErrorBanner message={getApiErrorMessage(error)} onRetry={() => refetch()} />;

  const hasAny =
    data.frequent_suspicious_hashes.length > 0 ||
    data.high_risk_files.length > 0 ||
    data.user_reported_suspicious.length > 0;

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold text-white tracking-tight">Internal Threat Intelligence</h2>
        <p className="text-sm text-slate-400">
          Hash sightings, high-risk detections, and analyst-flagged binaries derived strictly from internal scans.
        </p>
      </div>

      <Card className="border-purple-500/30 bg-purple-950/15 flex items-start gap-3">
        <Info className="h-5 w-5 text-purple-400 shrink-0 mt-0.5" />
        <p className="text-xs text-slate-300">{data.intelligence_source_notice}</p>
      </Card>

      {!hasAny ? (
        <EmptyState
          icon={Radar}
          title="No Internal Threats Recorded Yet"
          description="Once suspicious or ransomware binaries are detected or flagged by analysts, frequent hashes and threat trends will appear here."
        />
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
          <Card>
            <h3 className="text-base font-semibold text-white mb-3">Frequently Detected Suspicious Hashes</h3>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400">
                    <th className="pb-2">Sample</th>
                    <th className="pb-2">SHA-256</th>
                    <th className="pb-2">Sightings</th>
                    <th className="pb-2">Verdict</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/70">
                  {data.frequent_suspicious_hashes.map((h: {
                    sha256_hash: string;
                    sample_name: string;
                    sightings: number;
                    verdict: string;
                  }) => (
                    <tr key={h.sha256_hash}>
                      <td className="py-2.5 text-slate-200">{h.sample_name}</td>
                      <td className="py-2.5 font-mono text-slate-400">{h.sha256_hash.slice(0, 18)}...</td>
                      <td className="py-2.5 font-semibold text-cyan-300">{h.sightings}</td>
                      <td className="py-2.5">
                        <VerdictBadge verdict={h.verdict} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>

          <Card>
            <h3 className="text-base font-semibold text-white mb-3">High-Risk Files (Score ≥ 60)</h3>
            <div className="space-y-2.5">
              {data.high_risk_files.map((f: {
                scan_id: string;
                file_name: string;
                risk_level: string;
                risk_score: number;
                upload_timestamp: string;
              }) => (
                <div
                  key={f.scan_id}
                  onClick={() => navigate(`/scans/${f.scan_id}`)}
                  className="cursor-pointer rounded-lg border border-slate-800 bg-slate-900/60 p-3 flex items-center justify-between hover:border-cyan-500/40"
                >
                  <div>
                    <p className="text-sm font-medium text-cyan-300">{f.file_name}</p>
                    <p className="text-xs text-slate-400">{formatDateTime(f.upload_timestamp)}</p>
                  </div>
                  <RiskBadge level={f.risk_level} score={f.risk_score} />
                </div>
              ))}
            </div>
          </Card>
        </div>
      )}
    </div>
  );
}
