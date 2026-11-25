import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Download, FileText } from "lucide-react";
import { api, getApiErrorMessage } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { useToast } from "@/lib/toast";
import { formatDateTime } from "@/lib/utils";
import { Badge, Button, Card, EmptyState, ErrorBanner, LoadingState } from "@/components/ui/primitives";

export function ReportsPage() {
  const { user } = useAuth();
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const { data: reports, isLoading, error, refetch } = useQuery({
    queryKey: ["reports"],
    queryFn: async () => (await api.get("/api/reports")).data,
  });

  const adminPdfMut = useMutation({
    mutationFn: async () => (await api.post("/api/reports/admin/system")).data,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["reports"] });
      toast({ kind: "success", title: "Admin system PDF report generated" });
    },
    onError: (err) => toast({ kind: "error", title: "Report generation failed", description: getApiErrorMessage(err) }),
  });

  const downloadPdf = async (reportId: string, filename: string) => {
    try {
      const resp = await api.get(`/api/reports/${reportId}/download`, { responseType: "blob" });
      const url = URL.createObjectURL(new Blob([resp.data], { type: "application/pdf" }));
      const a = document.createElement("a");
      a.href = url;
      a.download = `${filename.replace(/[^a-zA-Z0-9._-]/g, "_")}.pdf`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      toast({ kind: "error", title: "Download failed", description: getApiErrorMessage(err) });
    }
  };

  if (isLoading) return <LoadingState message="Loading generated PDF reports..." />;
  if (error) return <ErrorBanner message={getApiErrorMessage(error)} onRetry={() => refetch()} />;

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h2 className="text-2xl font-bold text-white tracking-tight">PDF Reports</h2>
          <p className="text-sm text-slate-400">
            Dynamically generated ReportLab PDF security assessments backed by PostgreSQL records.
          </p>
        </div>
        {user?.role === "ADMIN" && (
          <Button onClick={() => adminPdfMut.mutate()} disabled={adminPdfMut.isPending}>
            <FileText className="h-4 w-4" />
            {adminPdfMut.isPending ? "Generating..." : "Generate System Executive PDF"}
          </Button>
        )}
      </div>

      {!reports || reports.length === 0 ? (
        <EmptyState
          icon={FileText}
          title="No PDF Reports Generated Yet"
          description="Open any scan detail page to generate an individual scan PDF report, or generate a system executive report (Admin)."
        />
      ) : (
        <Card>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="border-b border-slate-800 text-xs uppercase text-slate-400">
                  <th className="pb-2.5 pr-4">Target / Report</th>
                  <th className="pb-2.5 pr-4">Type</th>
                  <th className="pb-2.5 pr-4">Generated At</th>
                  <th className="pb-2.5">Download</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70">
                {reports.map((r: {
                  id: string;
                  file_name: string;
                  report_type: string;
                  generated_at: string;
                  exists: boolean;
                }) => (
                  <tr key={r.id}>
                    <td className="py-3 pr-4 font-medium text-white">{r.file_name}</td>
                    <td className="py-3 pr-4">
                      <Badge tone={r.report_type === "ADMIN_SYSTEM_PDF" ? "purple" : "cyan"}>{r.report_type}</Badge>
                    </td>
                    <td className="py-3 pr-4 text-xs text-slate-300">{formatDateTime(r.generated_at)}</td>
                    <td className="py-3">
                      <Button size="sm" variant="outline" disabled={!r.exists} onClick={() => downloadPdf(r.id, r.file_name)}>
                        <Download className="h-3.5 w-3.5" />
                        Download PDF
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}
    </div>
  );
}
