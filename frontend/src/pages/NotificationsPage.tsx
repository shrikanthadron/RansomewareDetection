import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Bell, CheckCheck, Trash2 } from "lucide-react";
import { api, getApiErrorMessage } from "@/lib/api";
import { useToast } from "@/lib/toast";
import type { AlertItem } from "@/lib/types";
import { formatDateTime } from "@/lib/utils";
import { Badge, Button, Card, EmptyState, ErrorBanner, LoadingState } from "@/components/ui/primitives";

export function NotificationsPage() {
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["alerts-list"],
    queryFn: async () => (await api.get<{ unread_count: number; items: AlertItem[] }>("/api/alerts")).data,
  });

  const markReadMut = useMutation({
    mutationFn: async (id: string) => (await api.post(`/api/alerts/${id}/read`)).data,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["alerts-list"] });
      queryClient.invalidateQueries({ queryKey: ["alerts-summary"] });
    },
  });

  const markAllMut = useMutation({
    mutationFn: async () => (await api.post("/api/alerts/mark-all-read")).data,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["alerts-list"] });
      queryClient.invalidateQueries({ queryKey: ["alerts-summary"] });
      toast({ kind: "success", title: "All notifications marked as read" });
    },
  });

  const deleteMut = useMutation({
    mutationFn: async (id: string) => (await api.delete(`/api/alerts/${id}`)).data,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["alerts-list"] });
      queryClient.invalidateQueries({ queryKey: ["alerts-summary"] });
    },
  });

  if (isLoading) return <LoadingState message="Loading security notifications..." />;
  if (error) return <ErrorBanner message={getApiErrorMessage(error)} onRetry={() => refetch()} />;

  const items = data?.items || [];

  return (
    <div className="space-y-6 max-w-4xl mx-auto">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h2 className="text-2xl font-bold text-white tracking-tight">Security Notifications</h2>
          <p className="text-sm text-slate-400">
            Unread alerts: {data?.unread_count || 0} • Stored persistently in PostgreSQL.
          </p>
        </div>
        {items.length > 0 && (
          <Button variant="outline" size="sm" onClick={() => markAllMut.mutate()}>
            <CheckCheck className="h-4 w-4" />
            Mark All Read
          </Button>
        )}
      </div>

      {items.length === 0 ? (
        <EmptyState
          icon={Bell}
          title="No Notifications"
          description="Ransomware detections, high-risk scans, model training updates, and live monitoring alerts appear here."
        />
      ) : (
        <div className="space-y-3">
          {items.map((a) => (
            <Card
              key={a.id}
              className={`flex flex-col sm:flex-row sm:items-center justify-between gap-4 ${
                a.is_read ? "opacity-75" : "border-cyan-500/40"
              }`}
            >
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <Badge tone={a.severity === "CRITICAL" || a.severity === "HIGH" ? "red" : a.severity === "MEDIUM" ? "orange" : "cyan"}>
                    {a.severity}
                  </Badge>
                  <span className="text-xs text-slate-400">{formatDateTime(a.created_at)}</span>
                  {!a.is_read && <Badge tone="purple">NEW</Badge>}
                </div>
                <h4 className="text-sm font-semibold text-white">{a.title}</h4>
                <p className="text-xs text-slate-300">{a.description}</p>
              </div>

              <div className="flex items-center gap-2 shrink-0">
                {!a.is_read && (
                  <Button size="sm" variant="outline" onClick={() => markReadMut.mutate(a.id)}>
                    Mark Read
                  </Button>
                )}
                <Button size="sm" variant="ghost" onClick={() => deleteMut.mutate(a.id)}>
                  <Trash2 className="h-4 w-4 text-slate-400 hover:text-red-400" />
                </Button>
              </div>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
