import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { RotateCcw, Save, ShieldCheck } from "lucide-react";
import { api, getApiErrorMessage } from "@/lib/api";
import { useToast } from "@/lib/toast";
import { formatDateTime } from "@/lib/utils";
import {
  Badge,
  Button,
  Card,
  ConfirmDialog,
  ErrorBanner,
  Input,
  LoadingState,
} from "@/components/ui/primitives";

export function AdminPanelPage() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [maxUploadSetting, setMaxUploadSetting] = useState("50");
  const [restoreId, setRestoreId] = useState<string | null>(null);

  const { data: metrics, isLoading, error, refetch } = useQuery({
    queryKey: ["admin-metrics"],
    queryFn: async () => (await api.get("/api/admin/metrics")).data,
  });

  const { data: quarantine } = useQuery({
    queryKey: ["quarantine-list"],
    queryFn: async () => (await api.get("/api/quarantine")).data,
  });

  const saveSysMut = useMutation({
    mutationFn: async () =>
      (await api.put("/api/settings/system", [{ setting_key: "max_upload_size_mb", setting_value: maxUploadSetting }])).data,
    onSuccess: () => toast({ kind: "success", title: "Global system setting updated" }),
    onError: (err) => toast({ kind: "error", title: "Update failed", description: getApiErrorMessage(err) }),
  });

  const restoreMut = useMutation({
    mutationFn: async (id: string) => (await api.post(`/api/quarantine/${id}/restore`)).data,
    onSuccess: () => {
      setRestoreId(null);
      queryClient.invalidateQueries({ queryKey: ["quarantine-list"] });
      queryClient.invalidateQueries({ queryKey: ["admin-metrics"] });
      toast({ kind: "success", title: "File verified and restored from quarantine" });
    },
    onError: (err) => {
      setRestoreId(null);
      toast({ kind: "error", title: "Restore failed", description: getApiErrorMessage(err) });
    },
  });

  if (isLoading) return <LoadingState message="Loading admin control plane..." />;
  if (error) return <ErrorBanner message={getApiErrorMessage(error)} onRetry={() => refetch()} />;

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold text-white tracking-tight">Administrator Control Panel</h2>
        <p className="text-sm text-slate-400">System-wide governance, upload policy configuration, and quarantine vault.</p>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3.5">
        {[
          { label: "Total Users", value: `${metrics.active_users}/${metrics.total_users} active` },
          { label: "System Scans", value: metrics.total_scans },
          { label: "Ransomware Hits", value: metrics.ransomware_detections },
          { label: "Quarantined Files", value: metrics.quarantined_files },
        ].map((item) => (
          <Card key={item.label} className="p-4">
            <p className="text-xs text-slate-400">{item.label}</p>
            <p className="text-xl font-bold text-white mt-1.5">{item.value}</p>
          </Card>
        ))}
      </div>

      <Card>
        <div className="flex items-center gap-2 mb-3">
          <ShieldCheck className="h-5 w-5 text-cyan-400" />
          <h3 className="text-base font-semibold text-white">Global Upload Limit Policy</h3>
        </div>
        <div className="flex flex-wrap items-end gap-3">
          <div className="w-56">
            <label className="block text-xs text-slate-400 mb-1">Max File Upload Size (MB)</label>
            <Input
              type="number"
              min={1}
              max={200}
              value={maxUploadSetting}
              onChange={(e) => setMaxUploadSetting(e.target.value)}
            />
          </div>
          <Button onClick={() => saveSysMut.mutate()} disabled={saveSysMut.isPending}>
            <Save className="h-4 w-4" />
            Save Policy
          </Button>
        </div>
      </Card>

      <Card>
        <h3 className="text-base font-semibold text-white mb-3">Quarantine Vault Records</h3>
        {!quarantine || quarantine.length === 0 ? (
          <p className="text-xs text-slate-400 py-6">No files currently in quarantine.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400">
                  <th className="pb-2 pr-3">Original Path</th>
                  <th className="pb-2 pr-3">SHA-256</th>
                  <th className="pb-2 pr-3">Status</th>
                  <th className="pb-2 pr-3">Quarantined At</th>
                  <th className="pb-2">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70">
                {quarantine.map((q: {
                  id: string;
                  original_path: string;
                  sha256_hash: string;
                  quarantine_status: string;
                  quarantined_at: string;
                }) => (
                  <tr key={q.id}>
                    <td className="py-2.5 pr-3 font-mono text-slate-200 max-w-xs truncate">{q.original_path}</td>
                    <td className="py-2.5 pr-3 font-mono text-slate-400">{q.sha256_hash.slice(0, 16)}...</td>
                    <td className="py-2.5 pr-3">
                      <Badge tone={q.quarantine_status === "QUARANTINED" ? "red" : "green"}>{q.quarantine_status}</Badge>
                    </td>
                    <td className="py-2.5 pr-3 text-slate-300">{formatDateTime(q.quarantined_at)}</td>
                    <td className="py-2.5">
                      {q.quarantine_status === "QUARANTINED" && (
                        <Button size="sm" variant="outline" onClick={() => setRestoreId(q.id)}>
                          <RotateCcw className="h-3.5 w-3.5" />
                          Restore
                        </Button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <ConfirmDialog
        open={!!restoreId}
        title="Restore Quarantined File?"
        description="RansomShield AI will verify the SHA-256 checksum of the quarantined artifact before restoring it to its original location."
        confirmLabel="Verify & Restore"
        danger={false}
        loading={restoreMut.isPending}
        onCancel={() => setRestoreId(null)}
        onConfirm={() => restoreId && restoreMut.mutate(restoreId)}
      />
    </div>
  );
}
