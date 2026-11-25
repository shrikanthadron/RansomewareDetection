import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Activity, AlertTriangle, Info, Play, RefreshCw, ShieldAlert, Square } from "lucide-react";
import { api, buildWsUrl, getApiErrorMessage } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { useToast } from "@/lib/toast";
import type { ProcessItem } from "@/lib/types";
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

export function LiveMonitoringPage() {
  const { user, token } = useAuth();
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const [search, setSearch] = useState("");
  const [liveProcs, setLiveProcs] = useState<ProcessItem[] | null>(null);
  const [confirmAction, setConfirmAction] = useState<{
    pid: number;
    name: string;
    action: "TERMINATE" | "QUARANTINE";
  } | null>(null);

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["monitoring-processes"],
    queryFn: async () => (await api.get("/api/monitoring/processes")).data,
    refetchInterval: 8000,
  });

  const { data: logs } = useQuery({
    queryKey: ["monitoring-logs"],
    queryFn: async () => (await api.get("/api/monitoring/logs")).data,
    refetchInterval: 10000,
  });

  useEffect(() => {
    if (!token) return;
    let ws: WebSocket | null = null;
    try {
      ws = new WebSocket(buildWsUrl(token));
      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);
          if (msg.type === "monitoring_snapshot" && Array.isArray(msg.processes)) {
            setLiveProcs(msg.processes);
          }
        } catch {
          // ignore
        }
      };
    } catch {
      // ignore
    }
    return () => {
      if (ws && ws.readyState === WebSocket.OPEN) ws.close();
    };
  }, [token]);

  const startMut = useMutation({
    mutationFn: async () => (await api.post("/api/monitoring/start", { poll_interval_sec: 5 })).data,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["monitoring-processes"] });
      queryClient.invalidateQueries({ queryKey: ["monitoring-status"] });
      toast({ kind: "success", title: "Opt-in live monitoring started" });
    },
    onError: (err) => toast({ kind: "error", title: "Failed to start monitor", description: getApiErrorMessage(err) }),
  });

  const stopMut = useMutation({
    mutationFn: async () => (await api.post("/api/monitoring/stop")).data,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["monitoring-processes"] });
      queryClient.invalidateQueries({ queryKey: ["monitoring-status"] });
      toast({ kind: "info", title: "Live monitoring stopped" });
    },
  });

  const actionMut = useMutation({
    mutationFn: async ({ pid, action }: { pid: number; action: string }) =>
      (await api.post(`/api/monitoring/processes/${pid}/action`, { action })).data,
    onSuccess: (res) => {
      setConfirmAction(null);
      queryClient.invalidateQueries({ queryKey: ["monitoring-logs"] });
      toast({ kind: "success", title: `Action ${res.action} executed`, description: res.detail });
      api.get("/api/monitoring/processes?refresh=true").then((r) => setLiveProcs(r.data.processes));
    },
    onError: (err) => {
      setConfirmAction(null);
      toast({ kind: "error", title: "Action blocked/failed", description: getApiErrorMessage(err) });
    },
  });

  const refreshSnapshot = async () => {
    try {
      const { data: res } = await api.get("/api/monitoring/processes?refresh=true");
      setLiveProcs(res.processes);
      toast({ kind: "info", title: "Process snapshot refreshed" });
    } catch (err) {
      toast({ kind: "error", title: "Snapshot refresh failed", description: getApiErrorMessage(err) });
    }
  };

  if (isLoading) return <LoadingState message="Loading monitoring subsystem..." />;
  if (error) return <ErrorBanner message={getApiErrorMessage(error)} onRetry={() => refetch()} />;

  const status = data.status;
  const processes: ProcessItem[] = liveProcs || data.processes || [];
  const filtered = processes.filter(
    (p) =>
      p.process_name.toLowerCase().includes(search.toLowerCase()) ||
      String(p.pid).includes(search) ||
      (p.executable_path || "").toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="space-y-6">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold text-white tracking-tight">Live Process Monitoring (Opt-In)</h2>
          <p className="text-sm text-slate-400">
            Safe, read-only psutil telemetry with explicit user consent and protected system-process guardrails.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          <Button variant="outline" onClick={refreshSnapshot}>
            <RefreshCw className="h-4 w-4" />
            Capture Snapshot
          </Button>
          {status.is_running ? (
            <Button variant="danger" onClick={() => stopMut.mutate()} disabled={stopMut.isPending}>
              <Square className="h-4 w-4" />
              Stop Monitoring
            </Button>
          ) : (
            <Button onClick={() => startMut.mutate()} disabled={startMut.isPending}>
              <Play className="h-4 w-4" />
              Start Monitoring
            </Button>
          )}
        </div>
      </div>

      {/* Platform transparency notice */}
      <Card className="border-cyan-500/25 bg-cyan-950/15">
        <div className="flex items-start gap-3">
          <Info className="h-5 w-5 text-cyan-400 shrink-0 mt-0.5" />
          <div className="text-xs text-slate-300 space-y-1">
            <p className="font-semibold text-cyan-200">
              Platform: {status.platform.platform} ({status.platform.release}) • Status:{" "}
              {status.is_running ? "MONITORING ACTIVE" : "STANDBY (OFF BY DEFAULT)"}
            </p>
            {status.platform.limitations.map((lim: string, idx: number) => (
              <p key={idx} className="text-slate-400">
                • {lim}
              </p>
            ))}
          </div>
        </div>
      </Card>

      <Card>
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
          <div className="flex items-center gap-2">
            <Activity className="h-4 w-4 text-cyan-400" />
            <h3 className="text-base font-semibold text-white">Observed Processes ({filtered.length})</h3>
          </div>
          <Input
            placeholder="Filter by process name, PID, or path..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="sm:w-72"
          />
        </div>

        {filtered.length === 0 ? (
          <p className="text-sm text-slate-400 py-10 text-center">
            No processes captured yet. Click &ldquo;Start Monitoring&rdquo; or &ldquo;Capture Snapshot&rdquo; to inspect active processes.
          </p>
        ) : (
          <div className="overflow-x-auto max-h-[480px]">
            <table className="w-full text-left text-xs">
              <thead className="sticky top-0 bg-slate-900 text-slate-400 border-b border-slate-800">
                <tr>
                  <th className="py-2.5 px-3">PID</th>
                  <th className="py-2.5 px-3">Process</th>
                  <th className="py-2.5 px-3">Executable Path</th>
                  <th className="py-2.5 px-3">Verdict</th>
                  <th className="py-2.5 px-3">Risk</th>
                  <th className="py-2.5 px-3">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70">
                {filtered.map((p) => (
                  <tr key={p.pid} className="hover:bg-slate-800/30">
                    <td className="py-2.5 px-3 font-mono text-slate-300">{p.pid}</td>
                    <td className="py-2.5 px-3">
                      <span className="font-medium text-white">{p.process_name}</span>
                      {p.is_protected && (
                        <Badge tone="cyan" className="ml-2">
                          OS Protected
                        </Badge>
                      )}
                    </td>
                    <td className="py-2.5 px-3 font-mono text-slate-400 max-w-xs truncate" title={p.executable_path || ""}>
                      {p.executable_path || "Access restricted"}
                    </td>
                    <td className="py-2.5 px-3">
                      <VerdictBadge verdict={p.classification} />
                    </td>
                    <td className="py-2.5 px-3">
                      <RiskBadge level={p.risk_level} score={p.risk_score} />
                    </td>
                    <td className="py-2.5 px-3">
                      <div className="flex items-center gap-1.5">
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => actionMut.mutate({ pid: p.pid, action: "FLAG" })}
                        >
                          Flag
                        </Button>
                        {user?.role === "ADMIN" && !p.is_protected && (
                          <>
                            <Button
                              size="sm"
                              variant="danger"
                              onClick={() =>
                                setConfirmAction({ pid: p.pid, name: p.process_name, action: "TERMINATE" })
                              }
                            >
                              Terminate
                            </Button>
                            {p.executable_path && (
                              <Button
                                size="sm"
                                variant="danger"
                                onClick={() =>
                                  setConfirmAction({ pid: p.pid, name: p.process_name, action: "QUARANTINE" })
                                }
                              >
                                Quarantine
                              </Button>
                            )}
                          </>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {/* Monitoring History Log */}
      <Card>
        <div className="flex items-center gap-2 mb-3">
          <AlertTriangle className="h-4 w-4 text-amber-400" />
          <h3 className="text-base font-semibold text-white">Notable Process & Action Logs</h3>
        </div>
        {!logs || logs.length === 0 ? (
          <p className="text-xs text-slate-400 py-4">No notable process alerts logged yet.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-slate-800 text-slate-400">
                <tr>
                  <th className="py-2 pr-3">Time</th>
                  <th className="py-2 pr-3">Process</th>
                  <th className="py-2 pr-3">PID</th>
                  <th className="py-2 pr-3">Classification</th>
                  <th className="py-2 pr-3">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {logs.slice(0, 20).map((l: {
                  id: string;
                  timestamp: string;
                  process_name: string;
                  process_id: number;
                  classification: string;
                  action_taken: string;
                }) => (
                  <tr key={l.id}>
                    <td className="py-2 pr-3 text-slate-400">{new Date(l.timestamp).toLocaleString()}</td>
                    <td className="py-2 pr-3 text-slate-200">{l.process_name}</td>
                    <td className="py-2 pr-3 font-mono">{l.process_id}</td>
                    <td className="py-2 pr-3">
                      <VerdictBadge verdict={l.classification} />
                    </td>
                    <td className="py-2 pr-3">
                      <Badge tone="purple">{l.action_taken}</Badge>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <ConfirmDialog
        open={!!confirmAction}
        title={
          confirmAction?.action === "QUARANTINE"
            ? `Terminate & Quarantine ${confirmAction?.name}?`
            : `Terminate Process ${confirmAction?.name}?`
        }
        description={
          confirmAction?.action === "QUARANTINE"
            ? `This will terminate PID ${confirmAction?.pid} and move its executable into the isolated RansomShield quarantine vault.`
            : `This will terminate running process ${confirmAction?.name} (PID ${confirmAction?.pid}). Protected Windows system processes are blocked automatically.`
        }
        confirmLabel={confirmAction?.action === "QUARANTINE" ? "Terminate & Quarantine" : "Terminate Process"}
        loading={actionMut.isPending}
        onCancel={() => setConfirmAction(null)}
        onConfirm={() => confirmAction && actionMut.mutate({ pid: confirmAction.pid, action: confirmAction.action })}
      />
    </div>
  );
}
