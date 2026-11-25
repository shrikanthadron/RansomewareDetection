import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { Search } from "lucide-react";
import { api, getApiErrorMessage } from "@/lib/api";
import { formatBytes, formatDateTime } from "@/lib/utils";
import {
  Button,
  Card,
  EmptyState,
  ErrorBanner,
  Input,
  LoadingState,
  RiskBadge,
  Select,
  VerdictBadge,
} from "@/components/ui/primitives";

export function ScanHistoryPage() {
  const navigate = useNavigate();
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState("");
  const [prediction, setPrediction] = useState("");
  const [riskLevel, setRiskLevel] = useState("");
  const [sortBy, setSortBy] = useState("upload_timestamp");
  const [sortDir, setSortDir] = useState("desc");

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["scan-history", page, search, prediction, riskLevel, sortBy, sortDir],
    queryFn: async () =>
      (
        await api.get("/api/scans", {
          params: {
            page,
            page_size: 12,
            search: search || undefined,
            prediction: prediction || undefined,
            risk_level: riskLevel || undefined,
            sort_by: sortBy,
            sort_dir: sortDir,
          },
        })
      ).data,
  });

  if (isLoading) return <LoadingState message="Querying PostgreSQL scan history..." />;
  if (error) return <ErrorBanner message={getApiErrorMessage(error)} onRetry={() => refetch()} />;

  const items = data.items || [];
  const totalPages = Math.max(1, Math.ceil((data.total || 0) / 12));

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold text-white tracking-tight">Scan History</h2>
        <p className="text-sm text-slate-400">Search, filter, and inspect static & ML binary scan records.</p>
      </div>

      <Card className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
        <div className="relative lg:col-span-2">
          <Search className="h-4 w-4 text-slate-500 absolute left-3 top-2.5" />
          <Input
            placeholder="Search filename, SHA-256, MD5, or user..."
            value={search}
            onChange={(e) => {
              setPage(1);
              setSearch(e.target.value);
            }}
            className="pl-9"
          />
        </div>
        <Select
          value={prediction}
          onChange={(e) => {
            setPage(1);
            setPrediction(e.target.value);
          }}
        >
          <option value="">All Classifications</option>
          <option value="BENIGN">BENIGN</option>
          <option value="SUSPICIOUS">SUSPICIOUS</option>
          <option value="RANSOMWARE">RANSOMWARE</option>
        </Select>
        <Select
          value={riskLevel}
          onChange={(e) => {
            setPage(1);
            setRiskLevel(e.target.value);
          }}
        >
          <option value="">All Risk Levels</option>
          <option value="LOW">LOW</option>
          <option value="GUARDED">GUARDED</option>
          <option value="MODERATE">MODERATE</option>
          <option value="HIGH">HIGH</option>
          <option value="CRITICAL">CRITICAL</option>
        </Select>
        <Select
          value={`${sortBy}:${sortDir}`}
          onChange={(e) => {
            const [sb, sd] = e.target.value.split(":");
            setSortBy(sb);
            setSortDir(sd);
          }}
        >
          <option value="upload_timestamp:desc">Newest First</option>
          <option value="upload_timestamp:asc">Oldest First</option>
          <option value="risk_score:desc">Highest Risk</option>
          <option value="risk_score:asc">Lowest Risk</option>
        </Select>
      </Card>

      {items.length === 0 ? (
        <EmptyState
          title="No Matching Scans Found"
          description="Try clearing search filters or scan an executable file to populate scan history."
          action={<Button onClick={() => navigate("/scanner")}>Scan a File</Button>}
        />
      ) : (
        <Card>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="border-b border-slate-800 text-xs uppercase text-slate-400">
                  <th className="pb-3 pr-4">File</th>
                  <th className="pb-3 pr-4">Classification</th>
                  <th className="pb-3 pr-4">Risk Score</th>
                  <th className="pb-3 pr-4">Scan Date</th>
                  <th className="pb-3 pr-4">Model</th>
                  <th className="pb-3">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70">
                {items.map((item: {
                  id: string;
                  original_file_name: string;
                  file_size: number;
                  prediction: string;
                  risk_level: string;
                  risk_score: number;
                  upload_timestamp: string;
                  model_label: string;
                  scan_status: string;
                }) => (
                  <tr
                    key={item.id}
                    onClick={() => navigate(`/scans/${item.id}`)}
                    className="cursor-pointer hover:bg-slate-800/40"
                  >
                    <td className="py-3 pr-4">
                      <p className="font-medium text-cyan-300">{item.original_file_name}</p>
                      <p className="text-xs text-slate-500">{formatBytes(item.file_size)}</p>
                    </td>
                    <td className="py-3 pr-4">
                      <VerdictBadge verdict={item.prediction} />
                    </td>
                    <td className="py-3 pr-4">
                      <RiskBadge level={item.risk_level} score={item.risk_score} />
                    </td>
                    <td className="py-3 pr-4 text-xs text-slate-300">{formatDateTime(item.upload_timestamp)}</td>
                    <td className="py-3 pr-4 text-xs text-slate-300">{item.model_label}</td>
                    <td className="py-3 text-xs text-slate-400">{item.scan_status}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="mt-4 flex items-center justify-between text-xs text-slate-400">
            <span>
              Page {page} of {totalPages} ({data.total} total)
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
      )}
    </div>
  );
}
