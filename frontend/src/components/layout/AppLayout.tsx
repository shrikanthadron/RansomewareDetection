import React, { useEffect, useState } from "react";
import { NavLink, Outlet, useNavigate } from "react-router-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Activity,
  BarChart3,
  Bell,
  Cpu,
  Database,
  FileSearch,
  FileText,
  History,
  LayoutDashboard,
  LogOut,
  Menu,
  Radar,
  ScrollText,
  Settings,
  Shield,
  ShieldCheck,
  Users,
  X,
} from "lucide-react";
import { api, buildWsUrl } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { useToast } from "@/lib/toast";
import { cn } from "@/lib/utils";

interface NavItem {
  label: string;
  to: string;
  icon: React.ComponentType<{ className?: string }>;
}

const USER_NAV: NavItem[] = [
  { label: "Overview", to: "/", icon: LayoutDashboard },
  { label: "File Scanner", to: "/scanner", icon: FileSearch },
  { label: "Live Monitoring", to: "/monitoring", icon: Activity },
  { label: "Scan History", to: "/history", icon: History },
  { label: "Threat Intelligence", to: "/threat-intel", icon: Radar },
  { label: "Dataset Manager", to: "/datasets", icon: Database },
  { label: "Model Analytics", to: "/models", icon: BarChart3 },
  { label: "Reports", to: "/reports", icon: FileText },
  { label: "Notifications", to: "/notifications", icon: Bell },
  { label: "Settings", to: "/settings", icon: Settings },
];

const ADMIN_NAV: NavItem[] = [
  { label: "Admin Panel", to: "/admin", icon: ShieldCheck },
  { label: "User Management", to: "/admin/users", icon: Users },
  { label: "Model Training", to: "/admin/training", icon: Cpu },
  { label: "System Logs", to: "/admin/logs", icon: ScrollText },
];

export function AppLayout() {
  const { user, token, logout } = useAuth();
  const { toast } = useToast();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [mobileOpen, setMobileOpen] = useState(false);

  const { data: alertData } = useQuery({
    queryKey: ["alerts-summary"],
    queryFn: async () => (await api.get("/api/alerts")).data,
    refetchInterval: 20000,
  });

  const { data: monitorStatus } = useQuery({
    queryKey: ["monitoring-status"],
    queryFn: async () => (await api.get("/api/monitoring/status")).data,
    refetchInterval: 15000,
  });

  useEffect(() => {
    if (!token) return;
    let ws: WebSocket | null = null;
    try {
      ws = new WebSocket(buildWsUrl(token));
      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);
          if (msg.type === "threat_alert") {
            toast({
              kind: msg.severity === "CRITICAL" || msg.severity === "HIGH" ? "error" : "warning",
              title: msg.title,
              description: "New threat alert recorded.",
            });
            queryClient.invalidateQueries({ queryKey: ["alerts-summary"] });
            queryClient.invalidateQueries({ queryKey: ["dashboard-overview"] });
          }
        } catch {
          // ignore malformed ws frame
        }
      };
    } catch {
      // ignore ws connection errors
    }
    return () => {
      if (ws && ws.readyState === WebSocket.OPEN) ws.close();
    };
  }, [token, toast, queryClient]);

  const unreadCount = alertData?.unread_count || 0;

  const handleLogout = async () => {
    await logout();
    navigate("/login");
  };

  const renderLinks = (items: NavItem[]) =>
    items.map((item) => (
      <NavLink
        key={item.to}
        to={item.to}
        end={item.to === "/" || item.to === "/admin"}
        onClick={() => setMobileOpen(false)}
        className={({ isActive }) =>
          cn(
            "flex items-center justify-between gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-all",
            isActive
              ? "bg-gradient-to-r from-cyan-500/20 to-blue-600/15 text-cyan-300 border border-cyan-500/30 shadow-sm"
              : "text-slate-400 hover:bg-slate-800/60 hover:text-slate-100 border border-transparent"
          )
        }
      >
        <span className="flex items-center gap-2.5 truncate">
          <item.icon className="h-4 w-4 shrink-0" />
          <span className="truncate">{item.label}</span>
        </span>
        {item.to === "/notifications" && unreadCount > 0 && (
          <span className="rounded-full bg-red-500/25 border border-red-500/40 px-2 py-0.5 text-[10px] font-bold text-red-300">
            {unreadCount}
          </span>
        )}
      </NavLink>
    ));

  return (
    <div className="min-h-screen flex bg-[#050814] text-slate-100">
      {/* Mobile overlay */}
      {mobileOpen && (
        <div
          className="fixed inset-0 z-40 bg-black/60 backdrop-blur-sm lg:hidden"
          onClick={() => setMobileOpen(false)}
        />
      )}

      {/* Sidebar */}
      <aside
        className={cn(
          "fixed inset-y-0 left-0 z-50 w-64 bg-[#070b19]/95 border-r border-slate-800/80 flex flex-col transition-transform duration-200 lg:static lg:translate-x-0",
          mobileOpen ? "translate-x-0" : "-translate-x-full"
        )}
      >
        <div className="flex items-center justify-between px-4 py-4 border-b border-slate-800/80">
          <div className="flex items-center gap-2.5">
            <div className="h-9 w-9 rounded-lg bg-gradient-to-br from-cyan-500 to-purple-600 flex items-center justify-center shadow-lg shadow-cyan-500/20">
              <Shield className="h-5 w-5 text-white" />
            </div>
            <div>
              <h1 className="text-sm font-bold tracking-tight text-white">RansomShield AI</h1>
              <p className="text-[11px] text-cyan-400/90">Supervised ML Defense</p>
            </div>
          </div>
          <button className="lg:hidden text-slate-400 hover:text-white" onClick={() => setMobileOpen(false)}>
            <X className="h-5 w-5" />
          </button>
        </div>

        <nav className="flex-1 overflow-y-auto px-3 py-4 space-y-5">
          <div>
            <p className="px-3 mb-2 text-[10px] font-semibold uppercase tracking-wider text-slate-500">
              Security Operations
            </p>
            <div className="space-y-1">{renderLinks(USER_NAV)}</div>
          </div>

          {user?.role === "ADMIN" && (
            <div>
              <p className="px-3 mb-2 text-[10px] font-semibold uppercase tracking-wider text-purple-400/80">
                Administration
              </p>
              <div className="space-y-1">{renderLinks(ADMIN_NAV)}</div>
            </div>
          )}
        </nav>

        <div className="border-t border-slate-800/80 p-3 space-y-2">
          <div className="rounded-lg bg-slate-900/70 border border-slate-800 px-3 py-2">
            <p className="text-xs font-semibold text-slate-200 truncate">{user?.full_name}</p>
            <p className="text-[11px] text-slate-400 truncate">{user?.email}</p>
            <span className="inline-block mt-1 rounded bg-cyan-500/15 border border-cyan-500/30 px-1.5 py-0.5 text-[10px] font-bold text-cyan-300">
              {user?.role}
            </span>
          </div>
          <button
            onClick={handleLogout}
            className="w-full flex items-center justify-center gap-2 rounded-lg border border-slate-800 py-2 text-xs font-medium text-slate-300 hover:bg-red-500/10 hover:border-red-500/30 hover:text-red-300 transition-colors"
          >
            <LogOut className="h-3.5 w-3.5" />
            Sign Out
          </button>
        </div>
      </aside>

      {/* Main Content */}
      <div className="flex-1 flex flex-col min-w-0">
        <header className="sticky top-0 z-30 h-14 border-b border-slate-800/80 bg-[#050814]/85 backdrop-blur-md px-4 lg:px-6 flex items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <button
              onClick={() => setMobileOpen(true)}
              className="lg:hidden rounded-lg p-1.5 text-slate-300 hover:bg-slate-800"
            >
              <Menu className="h-5 w-5" />
            </button>
            <span className="text-xs font-medium text-slate-400 hidden sm:inline">
              Endpoint Static PE & Supervised ML Threat Intelligence
            </span>
          </div>

          <div className="flex items-center gap-3">
            <NavLink
              to="/monitoring"
              className={cn(
                "inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-medium",
                monitorStatus?.is_running
                  ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-300"
                  : "border-slate-700 bg-slate-900/80 text-slate-400"
              )}
            >
              <span
                className={cn(
                  "h-2 w-2 rounded-full",
                  monitorStatus?.is_running ? "bg-emerald-400 animate-pulse" : "bg-slate-500"
                )}
              />
              Monitor: {monitorStatus?.is_running ? "Active" : "Standby"}
            </NavLink>

            <NavLink
              to="/notifications"
              className="relative rounded-lg border border-slate-800 bg-slate-900/70 p-2 text-slate-300 hover:text-cyan-300"
            >
              <Bell className="h-4 w-4" />
              {unreadCount > 0 && (
                <span className="absolute -top-1 -right-1 h-4 min-w-[16px] rounded-full bg-red-500 px-1 text-[10px] font-bold text-white flex items-center justify-center">
                  {unreadCount}
                </span>
              )}
            </NavLink>
          </div>
        </header>

        <main className="flex-1 p-4 lg:p-6 max-w-[1600px] w-full mx-auto">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
