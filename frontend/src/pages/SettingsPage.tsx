import React, { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { KeyRound, Save, Server, UserCog } from "lucide-react";
import { api, getApiErrorMessage } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { useToast } from "@/lib/toast";
import { Button, Card, Input, Select } from "@/components/ui/primitives";

export function SettingsPage() {
  const { user, refreshUser } = useAuth();
  const { toast } = useToast();

  const prefs = (user?.preferences || {}) as Record<string, unknown>;
  const [fullName, setFullName] = useState(user?.full_name || "");
  const [theme, setTheme] = useState((prefs.theme as string) || "dark");
  const [maxUploadMb, setMaxUploadMb] = useState(String(prefs.max_upload_mb ?? 50));
  const [notifyRansomware, setNotifyRansomware] = useState(Boolean(prefs.notify_ransomware ?? true));
  const [monitoringPoll, setMonitoringPoll] = useState(String(prefs.monitoring_poll_sec ?? 5));

  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");

  const { data: sysInfo } = useQuery({
    queryKey: ["system-info"],
    queryFn: async () => (await api.get("/api/settings/system-info")).data,
  });

  const profileMut = useMutation({
    mutationFn: async () =>
      (
        await api.put("/api/auth/profile", {
          full_name: fullName,
          preferences: {
            theme,
            max_upload_mb: Number(maxUploadMb) || 50,
            notify_ransomware: notifyRansomware,
            monitoring_poll_sec: Number(monitoringPoll) || 5,
          },
        })
      ).data,
    onSuccess: async () => {
      localStorage.setItem("rs_theme", theme);
      await refreshUser();
      toast({ kind: "success", title: "Profile & preferences saved" });
    },
    onError: (err) => toast({ kind: "error", title: "Save failed", description: getApiErrorMessage(err) }),
  });

  const pwMut = useMutation({
    mutationFn: async () =>
      (await api.post("/api/auth/change-password", { current_password: currentPassword, new_password: newPassword })).data,
    onSuccess: () => {
      setCurrentPassword("");
      setNewPassword("");
      toast({ kind: "success", title: "Password updated successfully" });
    },
    onError: (err) => toast({ kind: "error", title: "Password change failed", description: getApiErrorMessage(err) }),
  });

  return (
    <div className="space-y-6 max-w-4xl mx-auto">
      <div>
        <h2 className="text-2xl font-bold text-white tracking-tight">Account & Platform Settings</h2>
        <p className="text-sm text-slate-400">Manage profile details, scan & monitoring preferences, theme, and password.</p>
      </div>

      <Card>
        <div className="flex items-center gap-2 mb-4">
          <UserCog className="h-5 w-5 text-cyan-400" />
          <h3 className="text-base font-semibold text-white">Profile & Scan Preferences</h3>
        </div>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            profileMut.mutate();
          }}
          className="grid grid-cols-1 md:grid-cols-2 gap-4"
        >
          <div>
            <label className="block text-xs text-slate-300 mb-1">Full Name</label>
            <Input required value={fullName} onChange={(e) => setFullName(e.target.value)} />
          </div>
          <div>
            <label className="block text-xs text-slate-300 mb-1">Email (Read-only)</label>
            <Input disabled value={user?.email || ""} />
          </div>
          <div>
            <label className="block text-xs text-slate-300 mb-1">UI Theme</label>
            <Select value={theme} onChange={(e) => setTheme(e.target.value)}>
              <option value="dark">Cyber Dark (Default)</option>
              <option value="light">Clean Light</option>
            </Select>
          </div>
          <div>
            <label className="block text-xs text-slate-300 mb-1">Preferred Max Upload Limit (MB)</label>
            <Input
              type="number"
              min={1}
              max={100}
              value={maxUploadMb}
              onChange={(e) => setMaxUploadMb(e.target.value)}
            />
          </div>
          <div>
            <label className="block text-xs text-slate-300 mb-1">Monitoring Poll Interval (Seconds)</label>
            <Input
              type="number"
              min={2}
              max={30}
              value={monitoringPoll}
              onChange={(e) => setMonitoringPoll(e.target.value)}
            />
          </div>
          <div className="flex items-center gap-2 pt-5">
            <input
              id="notify_ransom"
              type="checkbox"
              checked={notifyRansomware}
              onChange={(e) => setNotifyRansomware(e.target.checked)}
              className="rounded border-slate-700 bg-slate-900"
            />
            <label htmlFor="notify_ransom" className="text-xs text-slate-300">
              Enable real-time ransomware alert notifications
            </label>
          </div>
          <div className="md:col-span-2 flex justify-end">
            <Button type="submit" disabled={profileMut.isPending}>
              <Save className="h-4 w-4" />
              Save Preferences
            </Button>
          </div>
        </form>
      </Card>

      <Card>
        <div className="flex items-center gap-2 mb-4">
          <KeyRound className="h-5 w-5 text-purple-400" />
          <h3 className="text-base font-semibold text-white">Change Password</h3>
        </div>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            pwMut.mutate();
          }}
          className="grid grid-cols-1 md:grid-cols-2 gap-4"
        >
          <div>
            <label className="block text-xs text-slate-300 mb-1">Current Password</label>
            <Input
              type="password"
              required
              value={currentPassword}
              onChange={(e) => setCurrentPassword(e.target.value)}
            />
          </div>
          <div>
            <label className="block text-xs text-slate-300 mb-1">New Password (min 8 chars)</label>
            <Input
              type="password"
              required
              minLength={8}
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
            />
          </div>
          <div className="md:col-span-2 flex justify-end">
            <Button type="submit" variant="secondary" disabled={pwMut.isPending}>
              Update Password
            </Button>
          </div>
        </form>
      </Card>

      {sysInfo && (
        <Card>
          <div className="flex items-center gap-2 mb-3">
            <Server className="h-5 w-5 text-cyan-400" />
            <h3 className="text-base font-semibold text-white">System Information</h3>
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 text-xs">
            <div className="rounded-lg bg-slate-900/70 p-3 border border-slate-800">
              <p className="text-slate-400">Application</p>
              <p className="font-semibold text-white">
                {sysInfo.app_name} v{sysInfo.app_version}
              </p>
            </div>
            <div className="rounded-lg bg-slate-900/70 p-3 border border-slate-800">
              <p className="text-slate-400">Database Engine</p>
              <p className="font-semibold text-cyan-300">{sysInfo.database_engine}</p>
            </div>
            <div className="rounded-lg bg-slate-900/70 p-3 border border-slate-800">
              <p className="text-slate-400">PE Schema / Host</p>
              <p className="font-semibold text-white">
                v{sysInfo.pe_schema_version} • {sysInfo.platform}
              </p>
            </div>
          </div>
        </Card>
      )}
    </div>
  );
}
