import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Search } from "lucide-react";
import { api, getApiErrorMessage } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { useToast } from "@/lib/toast";
import type { User } from "@/lib/types";
import { formatDateTime } from "@/lib/utils";
import { Badge, Button, Card, ErrorBanner, Input, LoadingState } from "@/components/ui/primitives";

export function UserManagementPage() {
  const { user: currentUser } = useAuth();
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [search, setSearch] = useState("");

  const { data: users, isLoading, error, refetch } = useQuery({
    queryKey: ["admin-users", search],
    queryFn: async () => (await api.get<User[]>("/api/admin/users", { params: { search } })).data,
  });

  const updateMut = useMutation({
    mutationFn: async ({ id, payload }: { id: string; payload: { role?: string; is_active?: boolean } }) =>
      (await api.patch(`/api/admin/users/${id}`, payload)).data,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["admin-users"] });
      toast({ kind: "success", title: "User account updated" });
    },
    onError: (err) => toast({ kind: "error", title: "Update failed", description: getApiErrorMessage(err) }),
  });

  if (isLoading) return <LoadingState message="Loading user directory..." />;
  if (error) return <ErrorBanner message={getApiErrorMessage(error)} onRetry={() => refetch()} />;

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h2 className="text-2xl font-bold text-white tracking-tight">User Management</h2>
          <p className="text-sm text-slate-400">Manage analyst accounts, roles, and account activation status.</p>
        </div>
        <div className="relative sm:w-72">
          <Search className="h-4 w-4 text-slate-500 absolute left-3 top-2.5" />
          <Input
            placeholder="Filter by name or email..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-9"
          />
        </div>
      </div>

      <Card>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 uppercase">
                <th className="pb-2.5 pr-3">Name</th>
                <th className="pb-2.5 pr-3">Email</th>
                <th className="pb-2.5 pr-3">Role</th>
                <th className="pb-2.5 pr-3">Status</th>
                <th className="pb-2.5 pr-3">Last Login</th>
                <th className="pb-2.5">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {(users || []).map((u) => (
                <tr key={u.id}>
                  <td className="py-3 pr-3 font-medium text-white">{u.full_name}</td>
                  <td className="py-3 pr-3 text-slate-300">{u.email}</td>
                  <td className="py-3 pr-3">
                    <Badge tone={u.role === "ADMIN" ? "purple" : "cyan"}>{u.role}</Badge>
                  </td>
                  <td className="py-3 pr-3">
                    <Badge tone={u.is_active ? "green" : "red"}>{u.is_active ? "ACTIVE" : "DISABLED"}</Badge>
                  </td>
                  <td className="py-3 pr-3 text-slate-400">{formatDateTime(u.last_login)}</td>
                  <td className="py-3">
                    {u.id !== currentUser?.id && (
                      <div className="flex gap-2">
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => updateMut.mutate({ id: u.id, payload: { is_active: !u.is_active } })}
                        >
                          {u.is_active ? "Deactivate" : "Activate"}
                        </Button>
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() =>
                            updateMut.mutate({ id: u.id, payload: { role: u.role === "ADMIN" ? "USER" : "ADMIN" } })
                          }
                        >
                          Make {u.role === "ADMIN" ? "USER" : "ADMIN"}
                        </Button>
                      </div>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}
