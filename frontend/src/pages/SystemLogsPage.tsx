import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, getApiErrorMessage } from "@/lib/api";
import { formatDateTime } from "@/lib/utils";
import { Badge, Button, Card, ErrorBanner, Input, LoadingState } from "@/components/ui/primitives";

export function SystemLogsPage() {
  const [page, setPage] = useState(1);
  const [actionFilter, setActionFilter] = useState("");

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["admin-logs", page, actionFilter],
    queryFn: async () =>
      (await api.get("/api/admin/logs", { params: { page, page_size: 25, action: actionFilter } })).data,
  });

  if (isLoading) return <LoadingState message="Loading audit logs..." />;
  if (error) return <ErrorBanner message={getApiErrorMessage(error)} onRetry={() => refetch()} />;

  const items = data.items || [];
  const totalPages = Math.max(1, Math.ceil((data.total || 0) / 25));

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h2 className="text-2xl font-bold text-white tracking-tight">System & Audit Logs</h2>
          <p className="text-sm text-slate-400">Immutable record of administrative, ML, quarantine, and security actions.</p>
        </div>
        <Input
          placeholder="Filter by action (e.g. MODEL_ACTIVATED)..."
          value={actionFilter}
          onChange={(e) => {
            setPage(1);
            setActionFilter(e.target.value);
          }}
          className="sm:w-72"
        />
      </div>

      <Card>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 uppercase">
                <th className="pb-2.5 pr-3">Timestamp</th>
                <th className="pb-2.5 pr-3">Actor</th>
                <th className="pb-2.5 pr-3">Action</th>
                <th className="pb-2.5 pr-3">Details</th>
                <th className="pb-2.5">IP Address</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {items.map((log: {
                id: string;
                created_at: string;
                admin_email: string;
                action: string;
                details: string;
                ip_address?: string;
              }) => (
                <tr key={log.id}>
                  <td className="py-2.5 pr-3 text-slate-400 whitespace-nowrap">{formatDateTime(log.created_at)}</td>
                  <td className="py-2.5 pr-3 text-slate-200">{log.admin_email}</td>
                  <td className="py-2.5 pr-3">
                    <Badge tone="cyan">{log.action}</Badge>
                  </td>
                  <td className="py-2.5 pr-3 text-slate-300">{log.details}</td>
                  <td className="py-2.5 font-mono text-slate-400">{log.ip_address || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="mt-4 flex items-center justify-between text-xs text-slate-400">
          <span>
            Page {page} of {totalPages}
          </span>
          <div className="flex gap-2">
            <Button size="sm" variant="outline" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>
              Previous
            </Button>
            <Button size="sm" variant="outline" disabled={page >= totalPages} onClick={() => setPage((p) => p + 1)}>
              Next
            </Button>
          </div>
        </div>
      </Card>
    </div>
  );
}
