import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Cpu, Database, Lock, Trash2, Upload } from "lucide-react";
import { api, getApiErrorMessage } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { useToast } from "@/lib/toast";
import type { DatasetItem } from "@/lib/types";
import { formatBytes } from "@/lib/utils";
import {
  Badge,
  Button,
  Card,
  ConfirmDialog,
  EmptyState,
  ErrorBanner,
  Input,
  LoadingState,
} from "@/components/ui/primitives";

export function DatasetManagerPage() {
  const { user } = useAuth();
  const { toast } = useToast();
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [labelColumn, setLabelColumn] = useState("label");
  const [file, setFile] = useState<File | null>(null);
  const [selectedDataset, setSelectedDataset] = useState<DatasetItem | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<DatasetItem | null>(null);

  const isAdmin = user?.role === "ADMIN";

  const { data: datasets, isLoading, error, refetch } = useQuery({
    queryKey: ["datasets"],
    queryFn: async () => (await api.get<DatasetItem[]>("/api/datasets")).data,
    enabled: isAdmin,
  });

  const uploadMut = useMutation({
    mutationFn: async () => {
      if (!file) throw new Error("Select a CSV file.");
      const form = new FormData();
      form.append("name", name);
      form.append("description", description);
      form.append("label_column", labelColumn);
      form.append("file", file);
      return (await api.post("/api/datasets/upload", form, { headers: { "Content-Type": "multipart/form-data" } })).data;
    },
    onSuccess: () => {
      setName("");
      setDescription("");
      setFile(null);
      queryClient.invalidateQueries({ queryKey: ["datasets"] });
      toast({ kind: "success", title: "Dataset validated and stored" });
    },
    onError: (err) => toast({ kind: "error", title: "Dataset upload failed", description: getApiErrorMessage(err) }),
  });

  const deleteMut = useMutation({
    mutationFn: async (id: string) => (await api.delete(`/api/datasets/${id}`)).data,
    onSuccess: () => {
      setDeleteTarget(null);
      setSelectedDataset(null);
      queryClient.invalidateQueries({ queryKey: ["datasets"] });
      toast({ kind: "info", title: "Dataset deleted" });
    },
    onError: (err) => toast({ kind: "error", title: "Delete failed", description: getApiErrorMessage(err) }),
  });

  if (!isAdmin) {
    return (
      <EmptyState
        icon={Lock}
        title="Administrator Access Required"
        description="Dataset upload, inspection, and management are restricted to ADMIN accounts on both the UI and backend API."
      />
    );
  }

  if (isLoading) return <LoadingState message="Loading datasets..." />;
  if (error) return <ErrorBanner message={getApiErrorMessage(error)} onRetry={() => refetch()} />;

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h2 className="text-2xl font-bold text-white tracking-tight">Dataset Manager</h2>
          <p className="text-sm text-slate-400">
            Upload labeled static PE CSV datasets, inspect class balance & missing values, and launch model training.
          </p>
        </div>
        <Button onClick={() => navigate("/admin/training")}>
          <Cpu className="h-4 w-4" />
          Train Model
        </Button>
      </div>

      {/* Upload Form */}
      <Card>
        <h3 className="text-base font-semibold text-white mb-4">Upload & Validate CSV Dataset</h3>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            uploadMut.mutate();
          }}
          className="grid grid-cols-1 md:grid-cols-2 gap-4"
        >
          <div>
            <label className="block text-xs text-slate-300 mb-1">Dataset Name</label>
            <Input required value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. PE Static Ransomware Corpus v1" />
          </div>
          <div>
            <label className="block text-xs text-slate-300 mb-1">Label Column Name</label>
            <Input required value={labelColumn} onChange={(e) => setLabelColumn(e.target.value)} placeholder="label" />
          </div>
          <div>
            <label className="block text-xs text-slate-300 mb-1">Description (Optional)</label>
            <Input value={description} onChange={(e) => setDescription(e.target.value)} placeholder="Source and feature notes" />
          </div>
          <div>
            <label className="block text-xs text-slate-300 mb-1">CSV File (Benign=0/benign, Ransomware=1/ransomware)</label>
            <Input type="file" accept=".csv" required onChange={(e) => setFile(e.target.files?.[0] || null)} />
          </div>
          <div className="md:col-span-2 flex justify-end">
            <Button type="submit" disabled={uploadMut.isPending || !file}>
              <Upload className="h-4 w-4" />
              {uploadMut.isPending ? "Validating CSV..." : "Upload & Validate Dataset"}
            </Button>
          </div>
        </form>
      </Card>

      {/* Dataset List */}
      {!datasets || datasets.length === 0 ? (
        <EmptyState
          icon={Database}
          title="No Datasets Uploaded Yet"
          description="Upload a labeled CSV dataset above (such as sample_data/ransomshield_sample_dataset.csv) to inspect statistics and train ML models."
        />
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
          <div className="space-y-3">
            {datasets.map((ds) => (
              <Card
                key={ds.id}
                className={`cursor-pointer border transition-all ${
                  selectedDataset?.id === ds.id ? "border-cyan-500" : "border-slate-800 hover:border-slate-700"
                }`}
              >
                <div onClick={() => setSelectedDataset(ds)}>
                  <div className="flex items-start justify-between gap-2">
                    <h4 className="font-semibold text-white text-sm">{ds.name}</h4>
                    <Badge tone={ds.metadata.matches_pe_schema ? "cyan" : "purple"}>
                      {ds.metadata.matches_pe_schema ? "PE Schema" : "Custom CSV"}
                    </Badge>
                  </div>
                  <p className="text-xs text-slate-400 mt-1">
                    {ds.sample_count} rows • {ds.benign_count} benign / {ds.ransomware_count} ransomware
                  </p>
                </div>
                <div className="mt-3 flex justify-end gap-2">
                  <Button size="sm" variant="outline" onClick={() => setSelectedDataset(ds)}>
                    Preview
                  </Button>
                  <Button size="sm" variant="danger" onClick={() => setDeleteTarget(ds)}>
                    <Trash2 className="h-3.5 w-3.5" />
                  </Button>
                </div>
              </Card>
            ))}
          </div>

          <Card className="lg:col-span-2">
            {!selectedDataset ? (
              <p className="text-sm text-slate-400 py-16 text-center">Select a dataset to view statistics and preview rows.</p>
            ) : (
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <h3 className="text-lg font-bold text-white">{selectedDataset.name}</h3>
                  <Button size="sm" onClick={() => navigate(`/admin/training?dataset=${selectedDataset.id}`)}>
                    Train Model on Dataset
                  </Button>
                </div>

                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
                  <div className="rounded-lg bg-slate-900/80 p-3 border border-slate-800">
                    <p className="text-slate-400">Rows / Cols</p>
                    <p className="font-bold text-white text-sm mt-0.5">
                      {selectedDataset.sample_count} × {selectedDataset.metadata.column_count}
                    </p>
                  </div>
                  <div className="rounded-lg bg-slate-900/80 p-3 border border-slate-800">
                    <p className="text-slate-400">Missing Values</p>
                    <p className="font-bold text-amber-300 text-sm mt-0.5">
                      {selectedDataset.metadata.missing_values_total ?? 0}
                    </p>
                  </div>
                  <div className="rounded-lg bg-slate-900/80 p-3 border border-slate-800">
                    <p className="text-slate-400">Duplicate Rows</p>
                    <p className="font-bold text-purple-300 text-sm mt-0.5">
                      {selectedDataset.metadata.duplicate_rows ?? 0}
                    </p>
                  </div>
                  <div className="rounded-lg bg-slate-900/80 p-3 border border-slate-800">
                    <p className="text-slate-400">Size on Disk</p>
                    <p className="font-bold text-cyan-300 text-sm mt-0.5">
                      {formatBytes(selectedDataset.metadata.file_size_bytes || 0)}
                    </p>
                  </div>
                </div>

                <div className="overflow-x-auto max-h-72 border border-slate-800 rounded-lg">
                  <table className="w-full text-left text-xs">
                    <thead className="bg-slate-900 text-slate-400 sticky top-0">
                      <tr>
                        {(selectedDataset.metadata.columns || []).slice(0, 8).map((c) => (
                          <th key={c} className="py-2 px-2.5 font-mono">
                            {c}
                          </th>
                        ))}
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/70">
                      {(selectedDataset.metadata.preview || []).slice(0, 8).map((row, idx) => (
                        <tr key={idx}>
                          {(selectedDataset.metadata.columns || []).slice(0, 8).map((c) => (
                            <td key={c} className="py-1.5 px-2.5 font-mono text-slate-300">
                              {String(row[c] ?? "")}
                            </td>
                          ))}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </Card>
        </div>
      )}

      <ConfirmDialog
        open={!!deleteTarget}
        title={`Delete Dataset "${deleteTarget?.name}"?`}
        description="This permanently deletes the CSV dataset and associated training records from PostgreSQL."
        confirmLabel="Delete Dataset"
        loading={deleteMut.isPending}
        onCancel={() => setDeleteTarget(null)}
        onConfirm={() => deleteTarget && deleteMut.mutate(deleteTarget.id)}
      />
    </div>
  );
}
