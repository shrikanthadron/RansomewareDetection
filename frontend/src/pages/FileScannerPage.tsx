import React, { useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, CheckCircle2, FileUp, Loader2, Shield, UploadCloud } from "lucide-react";
import { api, getApiErrorMessage } from "@/lib/api";
import { useToast } from "@/lib/toast";
import type { ScanDetail } from "@/lib/types";
import { formatBytes } from "@/lib/utils";
import { Button, Card, RiskBadge, VerdictBadge } from "@/components/ui/primitives";

const PIPELINE_STEPS = [
  "Validating file signature & size",
  "Computing SHA-256 & MD5 hashes",
  "Extracting static PE structure (no execution)",
  "Running supervised ML & Risk Engine",
  "Persisting telemetry to PostgreSQL",
];

export function FileScannerPage() {
  const inputRef = useRef<HTMLInputElement>(null);
  const navigate = useNavigate();
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [dragging, setDragging] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [activeStep, setActiveStep] = useState(0);
  const [result, setResult] = useState<ScanDetail | null>(null);
  const [error, setError] = useState("");

  const handleFilePick = (file: File | undefined) => {
    if (!file) return;
    setError("");
    setResult(null);
    setSelectedFile(file);
  };

  const handleScan = async () => {
    if (!selectedFile) return;
    setScanning(true);
    setError("");
    setActiveStep(0);

    const timer = setInterval(() => {
      setActiveStep((prev) => (prev < PIPELINE_STEPS.length - 1 ? prev + 1 : prev));
    }, 350);

    try {
      const formData = new FormData();
      formData.append("file", selectedFile);
      const { data } = await api.post<ScanDetail>("/api/scans/upload", formData, {
        headers: { "Content-Type": "multipart/form-data" },
      });
      setActiveStep(PIPELINE_STEPS.length - 1);
      setResult(data);
      queryClient.invalidateQueries({ queryKey: ["dashboard-overview"] });
      toast({
        kind: data.prediction?.prediction === "RANSOMWARE" ? "error" : "success",
        title: `Scan complete: ${data.prediction?.prediction}`,
        description: `Risk Score ${data.prediction?.risk_score.toFixed(1)}/100`,
      });
    } catch (err) {
      const msg = getApiErrorMessage(err, "File scan failed.");
      setError(msg);
      toast({ kind: "error", title: "Scan failed", description: msg });
    } finally {
      clearInterval(timer);
      setScanning(false);
    }
  };

  return (
    <div className="space-y-6 max-w-4xl mx-auto">
      <div>
        <h2 className="text-2xl font-bold text-white tracking-tight">Static PE File Scanner</h2>
        <p className="text-sm text-slate-400">
          Upload Windows PE executables (.exe, .dll, .sys, .bin, .scr) for safe static feature extraction and ML risk
          scoring. Uploaded files are never executed.
        </p>
      </div>

      <Card>
        <div
          onDragOver={(e) => {
            e.preventDefault();
            setDragging(true);
          }}
          onDragLeave={() => setDragging(false)}
          onDrop={(e) => {
            e.preventDefault();
            setDragging(false);
            handleFilePick(e.dataTransfer.files?.[0]);
          }}
          onClick={() => inputRef.current?.click()}
          className={`cursor-pointer rounded-xl border-2 border-dashed p-10 text-center transition-all ${
            dragging
              ? "border-cyan-400 bg-cyan-500/10"
              : "border-slate-700 hover:border-cyan-500/60 hover:bg-slate-900/60"
          }`}
        >
          <input
            ref={inputRef}
            type="file"
            accept=".exe,.dll,.sys,.bin,.scr"
            className="hidden"
            onChange={(e) => handleFilePick(e.target.files?.[0])}
          />
          <UploadCloud className="h-12 w-12 text-cyan-400 mx-auto mb-3" />
          <p className="text-base font-semibold text-white">
            {selectedFile ? selectedFile.name : "Drag & drop a PE binary here, or click to browse"}
          </p>
          <p className="text-xs text-slate-400 mt-1">
            {selectedFile
              ? `${formatBytes(selectedFile.size)} — Ready for static analysis`
              : "Supported formats: .exe, .dll, .sys, .bin, .scr"}
          </p>
        </div>

        <div className="mt-4 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2 text-xs text-slate-400">
            <Shield className="h-4 w-4 text-emerald-400" />
            Sandboxed non-executing static parser (pefile + SHA-256)
          </div>
          <Button onClick={handleScan} disabled={!selectedFile || scanning} size="lg">
            {scanning ? <Loader2 className="h-4 w-4 animate-spin" /> : <FileUp className="h-4 w-4" />}
            {scanning ? "Analyzing Binary..." : "Start Static & ML Scan"}
          </Button>
        </div>

        {scanning && (
          <div className="mt-6 space-y-2 border-t border-slate-800 pt-4">
            {PIPELINE_STEPS.map((step, idx) => (
              <div key={step} className="flex items-center gap-2.5 text-xs">
                {idx <= activeStep ? (
                  <CheckCircle2 className="h-4 w-4 text-cyan-400 shrink-0" />
                ) : (
                  <div className="h-4 w-4 rounded-full border border-slate-700 shrink-0" />
                )}
                <span className={idx <= activeStep ? "text-slate-100" : "text-slate-500"}>{step}</span>
              </div>
            ))}
          </div>
        )}

        {error && (
          <div className="mt-4 rounded-lg border border-red-500/40 bg-red-950/40 p-3 text-sm text-red-200">
            {error}
          </div>
        )}
      </Card>

      {result && result.prediction && (
        <Card className="border-cyan-500/30 space-y-4">
          {!result.prediction.ml_used && (
            <div className="rounded-lg border border-amber-500/40 bg-amber-950/40 p-3.5 flex items-start gap-2.5 text-xs text-amber-200">
              <AlertTriangle className="h-4 w-4 text-amber-400 shrink-0 mt-0.5" />
              <div>
                <p className="font-semibold">
                  {result.prediction.explanation?.ml_notice ||
                    "ML model not trained. Static analysis is available, but ML prediction is unavailable."}
                </p>
              </div>
            </div>
          )}

          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div>
              <p className="text-xs text-slate-400">Scan Result</p>
              <h3 className="text-lg font-bold text-white">{result.original_file_name}</h3>
              <p className="text-xs font-mono text-slate-400 mt-0.5">SHA-256: {result.sha256_hash}</p>
            </div>
            <div className="flex items-center gap-2.5">
              <VerdictBadge verdict={result.prediction.prediction} />
              <RiskBadge level={result.prediction.risk_level} score={result.prediction.risk_score} />
            </div>
          </div>

          <p className="text-sm text-slate-300">{result.prediction.explanation?.summary}</p>

          <div className="flex justify-end gap-3 pt-2">
            <Button variant="outline" onClick={() => navigate("/history")}>
              Scan History
            </Button>
            <Button onClick={() => navigate(`/scans/${result.id}`)}>Open Detailed Scan Report</Button>
          </div>
        </Card>
      )}
    </div>
  );
}
