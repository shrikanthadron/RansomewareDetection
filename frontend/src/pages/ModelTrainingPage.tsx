import React, { useEffect, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Cpu, Play, Square } from "lucide-react";
import { api, buildWsUrl, getApiErrorMessage } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { useToast } from "@/lib/toast";
import type { AlgorithmItem, DatasetItem } from "@/lib/types";
import { Badge, Button, Card, ErrorBanner, Input, LoadingState, Select } from "@/components/ui/primitives";

export function ModelTrainingPage() {
  const { token } = useAuth();
  const { toast } = useToast();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [searchParams] = useSearchParams();

  const [datasetId, setDatasetId] = useState(searchParams.get("dataset") || "");
  const [algorithmId, setAlgorithmId] = useState("");
  const [modelVersion, setModelVersion] = useState("1.0.0");
  const [testSize, setTestSize] = useState("0.2");
  const [featureSelection, setFeatureSelection] = useState("mutual_info");
  const [kFeatures, setKFeatures] = useState("20");
  const [cvFolds, setCvFolds] = useState("5");
  const [nEstimators, setNEstimators] = useState("200");

  const [activeJobId, setActiveJobId] = useState<string | null>(null);
  const [jobProgress, setJobProgress] = useState<{ progress: number; stage: string; logs: string[] } | null>(null);

  const { data: datasets, isLoading: loadingDs, error: errDs } = useQuery({
    queryKey: ["datasets"],
    queryFn: async () => (await api.get<DatasetItem[]>("/api/datasets")).data,
  });

  const { data: algorithms, isLoading: loadingAlgos } = useQuery({
    queryKey: ["algorithms"],
    queryFn: async () => (await api.get<AlgorithmItem[]>("/api/ml/algorithms")).data,
  });

  useEffect(() => {
    if (!datasetId && datasets && datasets.length > 0) setDatasetId(datasets[0].id);
  }, [datasets, datasetId]);

  useEffect(() => {
    if (!algorithmId && algorithms && algorithms.length > 0) setAlgorithmId(algorithms[0].id);
  }, [algorithms, algorithmId]);

  useEffect(() => {
    if (!token || !activeJobId) return;
    const ws = new WebSocket(buildWsUrl(token));
    ws.onmessage = (e) => {
      try {
        const msg = JSON.parse(e.data);
        if (msg.type === "training_progress" && msg.training_id === activeJobId) {
          setJobProgress({ progress: msg.progress, stage: msg.stage, logs: msg.logs || [] });
          if (msg.stage === "COMPLETED" || msg.stage === "FAILED" || msg.stage === "CANCELLED") {
            queryClient.invalidateQueries({ queryKey: ["ml-models"] });
            queryClient.invalidateQueries({ queryKey: ["dashboard-overview"] });
          }
        }
      } catch {
        // ignore
      }
    };
    const poller = setInterval(async () => {
      try {
        const { data } = await api.get(`/api/ml/train/${activeJobId}/status`);
        if (data.live_progress) {
          setJobProgress(data.live_progress);
        }
        if (["COMPLETED", "FAILED", "CANCELLED"].includes(data.training_status)) {
          clearInterval(poller);
          setJobProgress((prev) => ({
            progress: data.training_status === "COMPLETED" ? 100 : prev?.progress || 0,
            stage: data.training_status,
            logs: data.evaluation_details?.logs || prev?.logs || [],
          }));
          queryClient.invalidateQueries({ queryKey: ["ml-models"] });
        }
      } catch {
        // ignore
      }
    }, 2000);
    return () => {
      clearInterval(poller);
      if (ws.readyState === WebSocket.OPEN) ws.close();
    };
  }, [token, activeJobId, queryClient]);

  const startMut = useMutation({
    mutationFn: async () =>
      (
        await api.post("/api/ml/train", {
          dataset_id: datasetId,
          algorithm_id: algorithmId,
          model_version: modelVersion,
          test_size: Number(testSize),
          feature_selection: featureSelection,
          k_features: Number(kFeatures),
          cv_folds: Number(cvFolds),
          remove_duplicates: true,
          hyperparameters: { n_estimators: Number(nEstimators) },
        })
      ).data,
    onSuccess: (res) => {
      setActiveJobId(res.training_id);
      setJobProgress({ progress: 5, stage: "STARTED", logs: ["Training job queued..."] });
      toast({ kind: "info", title: "ML training job started" });
    },
    onError: (err) => toast({ kind: "error", title: "Failed to start training", description: getApiErrorMessage(err) }),
  });

  const cancelMut = useMutation({
    mutationFn: async () => activeJobId && (await api.post(`/api/ml/train/${activeJobId}/cancel`)).data,
    onSuccess: () => toast({ kind: "warning", title: "Cancellation signal sent" }),
  });

  if (loadingDs || loadingAlgos) return <LoadingState message="Loading ML training workspace..." />;
  if (errDs) return <ErrorBanner message={getApiErrorMessage(errDs)} />;

  return (
    <div className="space-y-6 max-w-4xl mx-auto">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h2 className="text-2xl font-bold text-white tracking-tight">Supervised ML Model Training</h2>
          <p className="text-sm text-slate-400">
            Train Random Forest, Decision Tree, SVM, or XGBoost with strict train-only preprocessing (zero leakage).
          </p>
        </div>
        <Button variant="outline" onClick={() => navigate("/models")}>
          Model Analytics
        </Button>
      </div>

      <Card>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            startMut.mutate();
          }}
          className="grid grid-cols-1 md:grid-cols-2 gap-4"
        >
          <div>
            <label className="block text-xs text-slate-300 mb-1">Training Dataset</label>
            <Select required value={datasetId} onChange={(e) => setDatasetId(e.target.value)}>
              {(datasets || []).map((d) => (
                <option key={d.id} value={d.id}>
                  {d.name} ({d.sample_count} rows)
                </option>
              ))}
            </Select>
          </div>
          <div>
            <label className="block text-xs text-slate-300 mb-1">Supervised Algorithm</label>
            <Select required value={algorithmId} onChange={(e) => setAlgorithmId(e.target.value)}>
              {(algorithms || []).map((a) => (
                <option key={a.id} value={a.id}>
                  {a.algorithm_name}
                </option>
              ))}
            </Select>
          </div>
          <div>
            <label className="block text-xs text-slate-300 mb-1">Model Version</label>
            <Input required value={modelVersion} onChange={(e) => setModelVersion(e.target.value)} />
          </div>
          <div>
            <label className="block text-xs text-slate-300 mb-1">Holdout Test Split (Default 80/20)</label>
            <Select value={testSize} onChange={(e) => setTestSize(e.target.value)}>
              <option value="0.2">20% Test / 80% Train (Recommended)</option>
              <option value="0.25">25% Test / 75% Train</option>
              <option value="0.3">30% Test / 70% Train</option>
            </Select>
          </div>
          <div>
            <label className="block text-xs text-slate-300 mb-1">Feature Selection (Fit on Train Only)</label>
            <Select value={featureSelection} onChange={(e) => setFeatureSelection(e.target.value)}>
              <option value="mutual_info">Mutual Information (SelectKBest)</option>
              <option value="chi2">Chi-Square (MinMaxScaler + SelectKBest)</option>
              <option value="none">Use All Numeric Features</option>
            </Select>
          </div>
          <div>
            <label className="block text-xs text-slate-300 mb-1">Top-K Features / Cross-Validation Folds</label>
            <div className="grid grid-cols-2 gap-2">
              <Input type="number" min={2} max={100} value={kFeatures} onChange={(e) => setKFeatures(e.target.value)} />
              <Select value={cvFolds} onChange={(e) => setCvFolds(e.target.value)}>
                <option value="0">No CV</option>
                <option value="3">3-Fold CV</option>
                <option value="5">5-Fold CV</option>
              </Select>
            </div>
          </div>
          <div>
            <label className="block text-xs text-slate-300 mb-1">Trees / Estimators (RF & XGBoost)</label>
            <Input type="number" min={50} max={500} value={nEstimators} onChange={(e) => setNEstimators(e.target.value)} />
          </div>
          <div className="md:col-span-2 flex justify-end gap-3 pt-2">
            <Button type="submit" disabled={startMut.isPending || !datasetId || !algorithmId}>
              <Play className="h-4 w-4" />
              Start Model Training
            </Button>
          </div>
        </form>
      </Card>

      {activeJobId && jobProgress && (
        <Card className="border-cyan-500/30 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Cpu className="h-5 w-5 text-cyan-400" />
              <h3 className="text-base font-semibold text-white">Training Progress</h3>
              <Badge tone={jobProgress.stage === "COMPLETED" ? "green" : jobProgress.stage === "FAILED" ? "red" : "cyan"}>
                {jobProgress.stage}
              </Badge>
            </div>
            {!["COMPLETED", "FAILED", "CANCELLED"].includes(jobProgress.stage) && (
              <Button size="sm" variant="danger" onClick={() => cancelMut.mutate()}>
                <Square className="h-3.5 w-3.5" />
                Cancel Job
              </Button>
            )}
          </div>

          <div className="h-3 w-full rounded-full bg-slate-800 overflow-hidden">
            <div className="h-full bg-cyan-500 transition-all duration-300" style={{ width: `${jobProgress.progress}%` }} />
          </div>

          <div className="rounded-lg bg-slate-950/90 border border-slate-800 p-3 font-mono text-xs text-slate-300 max-h-48 overflow-y-auto space-y-1">
            {jobProgress.logs.map((line, idx) => (
              <div key={idx}>{line}</div>
            ))}
          </div>

          {jobProgress.stage === "COMPLETED" && (
            <div className="flex justify-end">
              <Button onClick={() => navigate("/models")}>View Evaluation & Activate Model</Button>
            </div>
          )}
        </Card>
      )}
    </div>
  );
}
