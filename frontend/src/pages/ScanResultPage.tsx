import { useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertTriangle,
  Copy,
  Download,
  Flag,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import { api, getApiErrorMessage } from "@/lib/api";
import { useToast } from "@/lib/toast";
import type { ScanDetail } from "@/lib/types";
import { formatBytes, formatDateTime } from "@/lib/utils";
import {
  Badge,
  Button,
  Card,
  ConfirmDialog,
  ErrorBanner,
  Input,
  LoadingState,
  RiskBadge,
  VerdictBadge,
} from "@/components/ui/primitives";

export function ScanResultPage() {
  const { scanId } = useParams<{ scanId: string }>();
  const navigate = useNavigate();
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const [featureSearch, setFeatureSearch] = useState("");
  const [quarantineConfirm, setQuarantineConfirm] = useState(false);

  const { data: scan, isLoading, error, refetch } = useQuery({
    queryKey: ["scan-detail", scanId],
    queryFn: async () => (await api.get<ScanDetail>(`/api/scans/${scanId}`)).data,
    enabled: !!scanId,
  });

  const rescanMut = useMutation({
    mutationFn: async () => (await api.post<ScanDetail>(`/api/scans/${scanId}/rescan`)).data,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["scan-detail", scanId] });
      toast({ kind: "success", title: "File rescanned with latest active model" });
    },
    onError: (err) => toast({ kind: "error", title: "Rescan failed", description: getApiErrorMessage(err) }),
  });

  const flagMut = useMutation({
    mutationFn: async () => (await api.post(`/api/scans/${scanId}/flag`)).data,
    onSuccess: (res) => {
      queryClient.invalidateQueries({ queryKey: ["scan-detail", scanId] });
      toast({
        kind: "info",
        title: res.is_user_flagged ? "Flagged for Threat Intelligence" : "Flag removed",
      });
    },
  });

  const quarantineMut = useMutation({
    mutationFn: async () =>
      (await api.post("/api/quarantine/quarantine", { scan_id: scanId, file_path: scan?.file_path || "" })).data,
    onSuccess: () => {
      setQuarantineConfirm(false);
      toast({ kind: "success", title: "Sample moved to isolated quarantine vault" });
    },
    onError: (err) => {
      setQuarantineConfirm(false);
      toast({ kind: "error", title: "Quarantine failed", description: getApiErrorMessage(err) });
    },
  });

  const handleDownloadPdf = async () => {
    try {
      const { data: rep } = await api.post(`/api/reports/scan/${scanId}`);
      const resp = await api.get(`/api/reports/${rep.id}/download`, { responseType: "blob" });
      const url = URL.createObjectURL(new Blob([resp.data], { type: "application/pdf" }));
      const a = document.createElement("a");
      a.href = url;
      a.download = `RansomShield_Scan_${scanId?.slice(0, 8)}.pdf`;
      a.click();
      URL.revokeObjectURL(url);
      toast({ kind: "success", title: "PDF scan report downloaded" });
    } catch (err) {
      toast({ kind: "error", title: "PDF generation failed", description: getApiErrorMessage(err) });
    }
  };

  const copyText = async (label: string, val: string) => {
    await navigator.clipboard.writeText(val);
    toast({ kind: "info", title: `${label} copied to clipboard` });
  };

  if (isLoading) return <LoadingState message="Loading scan analysis report..." />;
  if (error || !scan) return <ErrorBanner message={getApiErrorMessage(error, "Scan not found.")} onRetry={() => refetch()} />;

  const pred = scan.prediction;
  const score = pred?.risk_score ?? 0;
  const barColor =
    score >= 81 ? "bg-red-500" : score >= 61 ? "bg-orange-500" : score >= 41 ? "bg-amber-400" : score >= 21 ? "bg-yellow-400" : "bg-emerald-500";

  const filteredFeatures = scan.features.filter((f) =>
    f.feature_name.toLowerCase().includes(featureSearch.toLowerCase())
  );

  return (
    <div className="space-y-6">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <button onClick={() => navigate("/history")} className="text-xs text-cyan-400 hover:underline mb-1">
            ← Back to Scan History
          </button>
          <h2 className="text-2xl font-bold text-white break-all">{scan.original_file_name}</h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Scanned on {formatDateTime(scan.upload_timestamp)} • Duration: {(scan.scan_duration ?? 0).toFixed(3)}s
          </p>
        </div>

        <div className="flex flex-wrap gap-2">
          <Button variant="outline" size="sm" onClick={() => rescanMut.mutate()} disabled={rescanMut.isPending}>
            <RefreshCw className={`h-3.5 w-3.5 ${rescanMut.isPending ? "animate-spin" : ""}`} />
            Rescan
          </Button>
          <Button variant="outline" size="sm" onClick={() => flagMut.mutate()}>
            <Flag className="h-3.5 w-3.5" />
            {scan.is_user_flagged ? "Unflag" : "Flag Suspicious"}
          </Button>
          <Button variant="danger" size="sm" onClick={() => setQuarantineConfirm(true)}>
            <ShieldAlert className="h-3.5 w-3.5" />
            Quarantine Sample
          </Button>
          <Button size="sm" onClick={handleDownloadPdf}>
            <Download className="h-3.5 w-3.5" />
            Download PDF Report
          </Button>
        </div>
      </div>

      {pred && !pred.ml_used && (
        <div className="rounded-xl border border-amber-500/40 bg-amber-950/40 p-4 flex items-start gap-3">
          <AlertTriangle className="h-5 w-5 text-amber-400 shrink-0 mt-0.5" />
          <div className="text-sm text-amber-200">
            <p className="font-semibold">
              {pred.explanation?.ml_notice ||
                "ML model not trained. Static analysis is available, but ML prediction is unavailable."}
            </p>
            <p className="text-xs opacity-85 mt-0.5">
              Risk assessment below is computed transparently from static PE structural & API heuristics.
            </p>
          </div>
        </div>
      )}

      {/* Top Grid: Verdict & Risk Gauge + Metadata */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        <Card className="lg:col-span-1 flex flex-col justify-between">
          <div>
            <p className="text-xs uppercase tracking-wider text-slate-400 font-semibold">Threat Verdict</p>
            <div className="flex items-center gap-3 mt-3">
              {pred?.prediction === "BENIGN" ? (
                <ShieldCheck className="h-10 w-10 text-emerald-400" />
              ) : (
                <ShieldAlert className="h-10 w-10 text-red-400" />
              )}
              <div>
                <VerdictBadge verdict={pred?.prediction || "PENDING"} />
                <div className="mt-1.5">
                  <RiskBadge level={pred?.risk_level || "LOW"} score={score} />
                </div>
              </div>
            </div>

            <div className="mt-5">
              <div className="flex justify-between text-xs mb-1.5">
                <span className="text-slate-400">Risk Score</span>
                <span className="font-bold text-white">{score.toFixed(1)} / 100</span>
              </div>
              <div className="h-3 w-full rounded-full bg-slate-800 overflow-hidden">
                <div className={`h-full ${barColor} transition-all`} style={{ width: `${Math.min(100, score)}%` }} />
              </div>
            </div>
          </div>

          <div className="mt-5 pt-4 border-t border-slate-800 grid grid-cols-2 gap-3 text-xs">
            <div>
              <p className="text-slate-400">Model Confidence</p>
              <p className="text-sm font-semibold text-white">{pred?.confidence.toFixed(1)}%</p>
            </div>
            <div>
              <p className="text-slate-400">Engine Used</p>
              <p className="text-sm font-semibold text-cyan-300 truncate">
                {pred?.ml_used ? `${pred.model_name} v${pred.model_version}` : "Static Heuristic"}
              </p>
            </div>
          </div>
        </Card>

        <Card className="lg:col-span-2 space-y-4">
          <h3 className="text-base font-semibold text-white">File Cryptographic & PE Summary</h3>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
            <div className="rounded-lg bg-slate-900/70 border border-slate-800 p-3">
              <p className="text-slate-400">File Type & Size</p>
              <p className="text-sm font-semibold text-white mt-0.5">
                {scan.file_type} • {formatBytes(scan.file_size)} ({scan.file_size.toLocaleString()} bytes)
              </p>
            </div>
            <div className="rounded-lg bg-slate-900/70 border border-slate-800 p-3">
              <p className="text-slate-400">Feature Schema Version</p>
              <p className="text-sm font-semibold text-cyan-300 mt-0.5">
                v{pred?.explanation?.schema_version || "1.0.0"} ({scan.features.length} features)
              </p>
            </div>
          </div>

          <div className="space-y-2 text-xs">
            <div className="flex items-center justify-between gap-2 rounded-lg bg-slate-900/70 border border-slate-800 p-3">
              <div className="min-w-0">
                <p className="text-slate-400">SHA-256</p>
                <p className="font-mono text-slate-200 truncate">{scan.sha256_hash}</p>
              </div>
              <Button size="sm" variant="ghost" onClick={() => copyText("SHA-256", scan.sha256_hash)}>
                <Copy className="h-3.5 w-3.5" />
              </Button>
            </div>
            <div className="flex items-center justify-between gap-2 rounded-lg bg-slate-900/70 border border-slate-800 p-3">
              <div className="min-w-0">
                <p className="text-slate-400">MD5</p>
                <p className="font-mono text-slate-200 truncate">{scan.md5_hash}</p>
              </div>
              <Button size="sm" variant="ghost" onClick={() => copyText("MD5", scan.md5_hash)}>
                <Copy className="h-3.5 w-3.5" />
              </Button>
            </div>
          </div>

          <p className="text-xs text-slate-300 leading-relaxed">{pred?.explanation?.summary}</p>
        </Card>
      </div>

      {/* Indicators & Model Feature Importances */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        <Card>
          <h3 className="text-base font-semibold text-white mb-3">Detected Static Risk Signals</h3>
          {pred?.explanation?.signals && pred.explanation.signals.length > 0 ? (
            <div className="space-y-2.5">
              {pred.explanation.signals.map((sig, i) => (
                <div key={i} className="rounded-lg border border-slate-800 bg-slate-900/60 p-3">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-sm font-semibold text-slate-100">{sig.indicator}</span>
                    <Badge tone={sig.severity === "HIGH" ? "red" : "orange"}>
                      {sig.severity} (+{sig.contribution})
                    </Badge>
                  </div>
                  <p className="text-xs text-slate-400 mt-1">{sig.detail}</p>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-sm text-slate-400 py-6">No high-risk static heuristic anomalies triggered.</p>
          )}
        </Card>

        <Card>
          <h3 className="text-base font-semibold text-white mb-3">PE Sections & Imported DLLs</h3>
          {pred?.explanation?.pe_metadata?.sections && pred.explanation.pe_metadata.sections.length > 0 ? (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400">
                    <th className="pb-2">Section</th>
                    <th className="pb-2">Raw Size</th>
                    <th className="pb-2">Entropy</th>
                    <th className="pb-2">Perms</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/70">
                  {pred.explanation.pe_metadata.sections.map((sec, idx) => (
                    <tr key={idx}>
                      <td className="py-2 font-mono text-cyan-300">{sec.name}</td>
                      <td className="py-2 text-slate-300">{formatBytes(sec.raw_size)}</td>
                      <td className="py-2 text-slate-300">{sec.entropy.toFixed(2)}</td>
                      <td className="py-2">
                        {sec.wx ? (
                          <Badge tone="red">W+X</Badge>
                        ) : (
                          <span className="text-slate-400">
                            {sec.executable ? "X " : ""}
                            {sec.writable ? "W" : "R"}
                          </span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p className="text-xs text-slate-400">No PE section table parsed.</p>
          )}
        </Card>
      </div>

      {/* Full Extracted Feature Table */}
      <Card>
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
          <h3 className="text-base font-semibold text-white">Extracted Static PE Feature Vector</h3>
          <Input
            placeholder="Filter features..."
            value={featureSearch}
            onChange={(e) => setFeatureSearch(e.target.value)}
            className="sm:w-64"
          />
        </div>
        <div className="overflow-x-auto max-h-96">
          <table className="w-full text-left text-xs">
            <thead className="sticky top-0 bg-slate-900">
              <tr className="border-b border-slate-800 text-slate-400">
                <th className="py-2 px-3">Feature Name</th>
                <th className="py-2 px-3">Type</th>
                <th className="py-2 px-3">Extracted Value</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {filteredFeatures.map((f) => (
                <tr key={f.feature_name}>
                  <td className="py-2 px-3 font-mono text-slate-200">{f.feature_name}</td>
                  <td className="py-2 px-3 text-slate-400">{f.feature_type}</td>
                  <td className="py-2 px-3 font-mono text-cyan-300">{f.feature_value}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      <ConfirmDialog
        open={quarantineConfirm}
        title="Confirm File Quarantine"
        description="This moves the stored binary sample into the isolated RansomShield quarantine vault and logs an audit entry. It will not delete the file."
        confirmLabel="Move to Quarantine"
        loading={quarantineMut.isPending}
        onCancel={() => setQuarantineConfirm(false)}
        onConfirm={() => quarantineMut.mutate()}
      />
    </div>
  );
}
