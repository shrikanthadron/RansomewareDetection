import { useQuery } from "@tanstack/react-query";
import { Link, useNavigate } from "react-router-dom";
import {
  Activity,
  AlertTriangle,
  Brain,
  CheckCircle2,
  FileSearch,
  Percent,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { api, getApiErrorMessage } from "@/lib/api";
import { formatDateTime } from "@/lib/utils";
import {
  Button,
  Card,
  EmptyState,
  ErrorBanner,
  LoadingState,
  RiskBadge,
  VerdictBadge,
} from "@/components/ui/primitives";

const PIE_COLORS = ["#10b981", "#f97316", "#ef4444"];

export function OverviewPage() {
  const navigate = useNavigate();
  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["dashboard-overview"],
    queryFn: async () => (await api.get("/api/dashboard/overview")).data,
  });

  if (isLoading) return <LoadingState message="Loading live PostgreSQL telemetry..." />;
  if (error) return <ErrorBanner message={getApiErrorMessage(error)} onRetry={() => refetch()} />;

  const m = data.metrics;
  const charts = data.charts;
  const recent = data.recent_activity || [];

  const statCards = [
    { label: "Total Scans", value: m.total_scans, icon: FileSearch, accent: "text-cyan-400" },
    { label: "Files Scanned Today", value: m.scans_today, icon: Activity, accent: "text-blue-400" },
    { label: "Ransomware Detections", value: m.ransomware_detections, icon: ShieldAlert, accent: "text-red-400" },
    { label: "Suspicious Files", value: m.suspicious_files, icon: AlertTriangle, accent: "text-orange-400" },
    { label: "Benign Files", value: m.benign_files, icon: CheckCircle2, accent: "text-emerald-400" },
    { label: "Detection Rate", value: `${m.detection_rate}%`, icon: Percent, accent: "text-purple-400" },
    {
      label: "Live Monitoring",
      value: m.monitoring_active ? "ACTIVE" : "STANDBY",
      icon: Activity,
      accent: m.monitoring_active ? "text-emerald-400" : "text-slate-400",
    },
    { label: "Trained Models", value: m.total_trained_models, icon: Brain, accent: "text-cyan-400" },
    {
      label: "Latest Model Accuracy",
      value: m.latest_model_accuracy !== null ? `${m.latest_model_accuracy}%` : "Not Trained",
      icon: ShieldCheck,
      accent: "text-blue-400",
    },
    { label: "Unread Threat Alerts", value: m.threat_alerts, icon: AlertTriangle, accent: "text-amber-400" },
  ];

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <h2 className="text-2xl font-bold text-white tracking-tight">Security Operations Overview</h2>
          <p className="text-sm text-slate-400">
            Real-time metrics queried directly from PostgreSQL scan, model, and telemetry records.
          </p>
        </div>
        <div className="flex items-center gap-2">
          {m.active_model_name ? (
            <span className="rounded-lg border border-cyan-500/30 bg-cyan-500/10 px-3 py-1.5 text-xs font-medium text-cyan-300">
              Active Model: {m.active_model_name}
            </span>
          ) : (
            <span className="rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-1.5 text-xs font-medium text-amber-300">
              No Active ML Model — Static Heuristics Only
            </span>
          )}
          <Button onClick={() => navigate("/scanner")}>Scan File</Button>
        </div>
      </div>

      {/* 10 Real Metrics */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3.5">
        {statCards.map((s) => (
          <Card key={s.label} className="p-4">
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium text-slate-400">{s.label}</span>
              <s.icon className={`h-4 w-4 ${s.accent}`} />
            </div>
            <p className="text-xl font-bold text-white mt-2">{s.value}</p>
          </Card>
        ))}
      </div>

      {m.total_scans === 0 && charts.model_comparison.length === 0 ? (
        <EmptyState
          title="No Scan or Model Telemetry Recorded Yet"
          description="Your PostgreSQL database is live and clean. Upload a PE executable (.exe/.dll) in File Scanner or train a supervised ML model to populate live charts."
          action={
            <div className="flex gap-3">
              <Button onClick={() => navigate("/scanner")}>Scan First Binary</Button>
              <Button variant="outline" onClick={() => navigate("/datasets")}>
                Dataset Manager
              </Button>
            </div>
          }
        />
      ) : (
        <>
          {/* Charts Grid (6 charts) */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
            <Card>
              <h3 className="text-sm font-semibold text-slate-200 mb-4">1. Scans Over Time (Last 14 Days)</h3>
              {charts.scans_over_time.length > 0 ? (
                <div className="h-64">
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={charts.scans_over_time}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                      <XAxis dataKey="date" stroke="#64748b" fontSize={11} />
                      <YAxis stroke="#64748b" fontSize={11} allowDecimals={false} />
                      <Tooltip contentStyle={{ backgroundColor: "#0f172a", borderColor: "#334155" }} />
                      <Area type="monotone" dataKey="total" stroke="#06b6d4" fill="#06b6d4" fillOpacity={0.2} />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              ) : (
                <p className="text-xs text-slate-500 py-20 text-center">No scan history yet.</p>
              )}
            </Card>

            <Card>
              <h3 className="text-sm font-semibold text-slate-200 mb-4">2. Benign vs Malicious Classifications</h3>
              {charts.classification_split.length > 0 ? (
                <div className="h-64">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie data={charts.classification_split} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={85} label>
                        {charts.classification_split.map((_: unknown, idx: number) => (
                          <Cell key={idx} fill={PIE_COLORS[idx % PIE_COLORS.length]} />
                        ))}
                      </Pie>
                      <Tooltip contentStyle={{ backgroundColor: "#0f172a", borderColor: "#334155" }} />
                      <Legend />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
              ) : (
                <p className="text-xs text-slate-500 py-20 text-center">No classification records yet.</p>
              )}
            </Card>

            <Card>
              <h3 className="text-sm font-semibold text-slate-200 mb-4">3. Risk Score Level Distribution</h3>
              {charts.risk_distribution.length > 0 ? (
                <div className="h-64">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={charts.risk_distribution}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                      <XAxis dataKey="level" stroke="#64748b" fontSize={11} />
                      <YAxis stroke="#64748b" fontSize={11} allowDecimals={false} />
                      <Tooltip contentStyle={{ backgroundColor: "#0f172a", borderColor: "#334155" }} />
                      <Bar dataKey="count" fill="#3b82f6" radius={[6, 6, 0, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              ) : (
                <p className="text-xs text-slate-500 py-20 text-center">No risk distribution data yet.</p>
              )}
            </Card>

            <Card>
              <h3 className="text-sm font-semibold text-slate-200 mb-4">4. Detection Trends (Ransomware vs Benign)</h3>
              {charts.scans_over_time.length > 0 ? (
                <div className="h-64">
                  <ResponsiveContainer width="100%" height="100%">
                    <LineChart data={charts.scans_over_time}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                      <XAxis dataKey="date" stroke="#64748b" fontSize={11} />
                      <YAxis stroke="#64748b" fontSize={11} allowDecimals={false} />
                      <Tooltip contentStyle={{ backgroundColor: "#0f172a", borderColor: "#334155" }} />
                      <Legend />
                      <Line type="monotone" dataKey="ransomware" stroke="#ef4444" strokeWidth={2} />
                      <Line type="monotone" dataKey="suspicious" stroke="#f97316" strokeWidth={2} />
                      <Line type="monotone" dataKey="benign" stroke="#10b981" strokeWidth={2} />
                    </LineChart>
                  </ResponsiveContainer>
                </div>
              ) : (
                <p className="text-xs text-slate-500 py-20 text-center">No detection trend data yet.</p>
              )}
            </Card>

            <Card>
              <h3 className="text-sm font-semibold text-slate-200 mb-4">5. Model Performance Comparison (%)</h3>
              {charts.model_comparison.length > 0 ? (
                <div className="h-64">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={charts.model_comparison}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                      <XAxis dataKey="name" stroke="#64748b" fontSize={10} />
                      <YAxis domain={[0, 100]} stroke="#64748b" fontSize={11} />
                      <Tooltip contentStyle={{ backgroundColor: "#0f172a", borderColor: "#334155" }} />
                      <Legend />
                      <Bar dataKey="accuracy" fill="#06b6d4" />
                      <Bar dataKey="recall" fill="#8b5cf6" />
                      <Bar dataKey="f1_score" fill="#3b82f6" />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              ) : (
                <p className="text-xs text-slate-500 py-20 text-center">No trained ML models recorded yet.</p>
              )}
            </Card>

            <Card>
              <h3 className="text-sm font-semibold text-slate-200 mb-4">6. Threat Alert Severity Distribution</h3>
              {charts.severity_distribution.length > 0 ? (
                <div className="h-64">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={charts.severity_distribution}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                      <XAxis dataKey="severity" stroke="#64748b" fontSize={11} />
                      <YAxis stroke="#64748b" fontSize={11} allowDecimals={false} />
                      <Tooltip contentStyle={{ backgroundColor: "#0f172a", borderColor: "#334155" }} />
                      <Bar dataKey="count" fill="#8b5cf6" radius={[6, 6, 0, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              ) : (
                <p className="text-xs text-slate-500 py-20 text-center">No threat alerts generated yet.</p>
              )}
            </Card>
          </div>

          {/* Recent Activity */}
          <Card>
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-base font-semibold text-white">Recent Scan Activity</h3>
              <Link to="/history" className="text-xs text-cyan-400 hover:underline">
                View Full History
              </Link>
            </div>
            {recent.length === 0 ? (
              <p className="text-sm text-slate-400 py-6 text-center">No recent scans recorded.</p>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-sm">
                  <thead>
                    <tr className="border-b border-slate-800 text-xs uppercase text-slate-400">
                      <th className="pb-2.5 pr-4">File Name</th>
                      <th className="pb-2.5 pr-4">SHA-256</th>
                      <th className="pb-2.5 pr-4">Scan Time</th>
                      <th className="pb-2.5 pr-4">Prediction</th>
                      <th className="pb-2.5 pr-4">Risk Score</th>
                      <th className="pb-2.5">Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/70">
                    {recent.map((row: {
                      scan_id: string;
                      file_name: string;
                      sha256_hash: string;
                      upload_timestamp: string;
                      prediction: string;
                      risk_score: number;
                      risk_level: string;
                      scan_status: string;
                    }) => (
                      <tr
                        key={row.scan_id}
                        onClick={() => navigate(`/scans/${row.scan_id}`)}
                        className="cursor-pointer hover:bg-slate-800/40 transition-colors"
                      >
                        <td className="py-3 pr-4 font-medium text-cyan-300">{row.file_name}</td>
                        <td className="py-3 pr-4 font-mono text-xs text-slate-400">
                          {row.sha256_hash.slice(0, 16)}...
                        </td>
                        <td className="py-3 pr-4 text-xs text-slate-300">{formatDateTime(row.upload_timestamp)}</td>
                        <td className="py-3 pr-4">
                          <VerdictBadge verdict={row.prediction} />
                        </td>
                        <td className="py-3 pr-4">
                          <RiskBadge level={row.risk_level} score={row.risk_score} />
                        </td>
                        <td className="py-3 text-xs text-slate-300">{row.scan_status}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Card>
        </>
      )}
    </div>
  );
}
