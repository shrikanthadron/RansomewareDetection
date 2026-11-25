import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CheckCircle2, Cpu } from "lucide-react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Legend,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { api, getApiErrorMessage } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { useToast } from "@/lib/toast";
import type { TrainedModelItem } from "@/lib/types";
import {
  Badge,
  Button,
  Card,
  EmptyState,
  ErrorBanner,
  LoadingState,
} from "@/components/ui/primitives";

export function ModelAnalyticsPage() {
  const { user } = useAuth();
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const { data: models, isLoading, error, refetch } = useQuery({
    queryKey: ["ml-models"],
    queryFn: async () => (await api.get<TrainedModelItem[]>("/api/ml/models")).data,
  });

  const activateMut = useMutation({
    mutationFn: async (id: string) => (await api.post(`/api/ml/models/${id}/activate`)).data,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["ml-models"] });
      queryClient.invalidateQueries({ queryKey: ["dashboard-overview"] });
      toast({ kind: "success", title: "Production ML model activated" });
    },
    onError: (err) => toast({ kind: "error", title: "Activation failed", description: getApiErrorMessage(err) }),
  });

  if (isLoading) return <LoadingState message="Loading ML model evaluation telemetry..." />;
  if (error) return <ErrorBanner message={getApiErrorMessage(error)} onRetry={() => refetch()} />;

  const completed = (models || []).filter((m) => m.training_status === "COMPLETED");
  const activeModel = completed.find((m) => m.is_active);
  const selected = completed.find((m) => m.id === selectedId) || activeModel || completed[0] || null;

  if (!models || models.length === 0) {
    return (
      <EmptyState
        icon={Cpu}
        title="No Trained ML Models Yet"
        description="Administrators can upload a labeled PE CSV dataset and train Random Forest, Decision Tree, SVM, or XGBoost models under Model Training."
      />
    );
  }

  const comparisonData = completed.map((m) => ({
    name: `${m.algorithm_name} (${m.model_version})`,
    Accuracy: Number(((m.accuracy || 0) * 100).toFixed(2)),
    Precision: Number(((m.precision || 0) * 100).toFixed(2)),
    Recall: Number(((m.recall || 0) * 100).toFixed(2)),
    F1: Number(((m.f1_score || 0) * 100).toFixed(2)),
  }));

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h2 className="text-2xl font-bold text-white tracking-tight">ML Model Analytics</h2>
          <p className="text-sm text-slate-400">
            Compare evaluation metrics, confusion matrices, ROC curves, and manage the active production model.
          </p>
        </div>
        {activeModel && (
          <Badge tone="green" className="px-3 py-1.5 text-xs">
            <CheckCircle2 className="h-3.5 w-3.5" />
            Active Production Model: {activeModel.algorithm_name} v{activeModel.model_version}
          </Badge>
        )}
      </div>

      {/* Model Table */}
      <Card>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 uppercase">
                <th className="pb-2.5 pr-3">Model</th>
                <th className="pb-2.5 pr-3">Dataset</th>
                <th className="pb-2.5 pr-3">Status</th>
                <th className="pb-2.5 pr-3">Accuracy</th>
                <th className="pb-2.5 pr-3">Precision</th>
                <th className="pb-2.5 pr-3">Recall</th>
                <th className="pb-2.5 pr-3">F1</th>
                <th className="pb-2.5 pr-3">ROC-AUC</th>
                <th className="pb-2.5">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {models.map((m) => (
                <tr
                  key={m.id}
                  onClick={() => m.training_status === "COMPLETED" && setSelectedId(m.id)}
                  className={`cursor-pointer hover:bg-slate-800/40 ${selected?.id === m.id ? "bg-cyan-950/20" : ""}`}
                >
                  <td className="py-3 pr-3 font-medium text-white">
                    {m.algorithm_name} <span className="text-slate-400">v{m.model_version}</span>
                  </td>
                  <td className="py-3 pr-3 text-slate-300">{m.dataset_name}</td>
                  <td className="py-3 pr-3">
                    {m.is_active ? (
                      <Badge tone="green">ACTIVE</Badge>
                    ) : (
                      <Badge tone={m.training_status === "COMPLETED" ? "cyan" : "neutral"}>{m.training_status}</Badge>
                    )}
                  </td>
                  <td className="py-3 pr-3">{m.accuracy != null ? `${(m.accuracy * 100).toFixed(2)}%` : "—"}</td>
                  <td className="py-3 pr-3">{m.precision != null ? `${(m.precision * 100).toFixed(2)}%` : "—"}</td>
                  <td className="py-3 pr-3 text-cyan-300 font-semibold">
                    {m.recall != null ? `${(m.recall * 100).toFixed(2)}%` : "—"}
                  </td>
                  <td className="py-3 pr-3">{m.f1_score != null ? `${(m.f1_score * 100).toFixed(2)}%` : "—"}</td>
                  <td className="py-3 pr-3">{m.roc_auc != null ? m.roc_auc.toFixed(4) : "—"}</td>
                  <td className="py-3">
                    {user?.role === "ADMIN" && m.training_status === "COMPLETED" && !m.is_active && (
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={(e) => {
                          e.stopPropagation();
                          activateMut.mutate(m.id);
                        }}
                      >
                        Activate
                      </Button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      {selected && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
          {/* Confusion Matrix */}
          <Card>
            <h3 className="text-base font-semibold text-white mb-3">
              Confusion Matrix — {selected.algorithm_name} (v{selected.model_version})
            </h3>
            {selected.confusion_matrix ? (
              <div className="grid grid-cols-2 gap-3 text-center my-4">
                <div className="rounded-lg bg-emerald-500/15 border border-emerald-500/30 p-4">
                  <p className="text-xs text-slate-400">True Negative (Benign)</p>
                  <p className="text-2xl font-bold text-emerald-300 mt-1">{selected.confusion_matrix.tn}</p>
                </div>
                <div className="rounded-lg bg-amber-500/15 border border-amber-500/30 p-4">
                  <p className="text-xs text-slate-400">False Positive (FPR {(selected.evaluation_details?.fpr ?? 0) * 100}%)</p>
                  <p className="text-2xl font-bold text-amber-300 mt-1">{selected.confusion_matrix.fp}</p>
                </div>
                <div className="rounded-lg bg-red-500/15 border border-red-500/30 p-4">
                  <p className="text-xs text-slate-400">False Negative (Missed)</p>
                  <p className="text-2xl font-bold text-red-300 mt-1">{selected.confusion_matrix.fn}</p>
                </div>
                <div className="rounded-lg bg-cyan-500/15 border border-cyan-500/30 p-4">
                  <p className="text-xs text-slate-400">True Positive (Ransomware)</p>
                  <p className="text-2xl font-bold text-cyan-300 mt-1">{selected.confusion_matrix.tp}</p>
                </div>
              </div>
            ) : null}
            <p className="text-xs text-slate-400">
              Training duration: {selected.evaluation_details?.training_duration_sec}s • Holdout test samples:{" "}
              {selected.evaluation_details?.test_samples}
            </p>
          </Card>

          {/* ROC Curve */}
          <Card>
            <h3 className="text-base font-semibold text-white mb-3">
              ROC Curve (AUC = {selected.roc_auc?.toFixed(4)})
            </h3>
            <div className="h-60">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={selected.evaluation_details?.roc_curve || []}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis dataKey="x" stroke="#64748b" fontSize={11} label={{ value: "FPR", position: "insideBottom", offset: -3 }} />
                  <YAxis stroke="#64748b" fontSize={11} />
                  <Tooltip contentStyle={{ backgroundColor: "#0f172a", borderColor: "#334155" }} />
                  <Line type="monotone" dataKey="y" stroke="#06b6d4" strokeWidth={2.5} dot={false} />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </Card>

          {/* Model Comparison */}
          <Card className="lg:col-span-2">
            <h3 className="text-base font-semibold text-white mb-3">Trained Model Comparison (%)</h3>
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={comparisonData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis dataKey="name" stroke="#64748b" fontSize={11} />
                  <YAxis domain={[0, 100]} stroke="#64748b" fontSize={11} />
                  <Tooltip contentStyle={{ backgroundColor: "#0f172a", borderColor: "#334155" }} />
                  <Legend />
                  <Bar dataKey="Accuracy" fill="#06b6d4" />
                  <Bar dataKey="Precision" fill="#3b82f6" />
                  <Bar dataKey="Recall" fill="#8b5cf6" />
                  <Bar dataKey="F1" fill="#10b981" />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </Card>
        </div>
      )}
    </div>
  );
}
