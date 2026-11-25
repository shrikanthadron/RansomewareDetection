import React from "react";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { AuthProvider, useAuth } from "@/lib/auth";
import { ToastProvider } from "@/lib/toast";
import { AppLayout } from "@/components/layout/AppLayout";
import { LoadingState } from "@/components/ui/primitives";
import { LoginPage } from "@/pages/LoginPage";
import { RegisterPage } from "@/pages/RegisterPage";
import { OverviewPage } from "@/pages/OverviewPage";
import { FileScannerPage } from "@/pages/FileScannerPage";
import { ScanResultPage } from "@/pages/ScanResultPage";
import { LiveMonitoringPage } from "@/pages/LiveMonitoringPage";
import { ScanHistoryPage } from "@/pages/ScanHistoryPage";
import { ThreatIntelPage } from "@/pages/ThreatIntelPage";
import { DatasetManagerPage } from "@/pages/DatasetManagerPage";
import { ModelAnalyticsPage } from "@/pages/ModelAnalyticsPage";
import { ReportsPage } from "@/pages/ReportsPage";
import { NotificationsPage } from "@/pages/NotificationsPage";
import { SettingsPage } from "@/pages/SettingsPage";
import { AdminPanelPage } from "@/pages/AdminPanelPage";
import { UserManagementPage } from "@/pages/UserManagementPage";
import { ModelTrainingPage } from "@/pages/ModelTrainingPage";
import { SystemLogsPage } from "@/pages/SystemLogsPage";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
});

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { user, loading } = useAuth();
  if (loading) return <LoadingState message="Verifying security session..." />;
  if (!user) return <Navigate to="/login" replace />;
  return <>{children}</>;
}

function AdminRoute({ children }: { children: React.ReactNode }) {
  const { user, loading } = useAuth();
  if (loading) return <LoadingState message="Verifying administrator privileges..." />;
  if (!user) return <Navigate to="/login" replace />;
  if (user.role !== "ADMIN") return <Navigate to="/" replace />;
  return <>{children}</>;
}

export function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <ToastProvider>
        <AuthProvider>
          <BrowserRouter>
            <Routes>
              <Route path="/login" element={<LoginPage />} />
              <Route path="/register" element={<RegisterPage />} />

              <Route
                path="/"
                element={
                  <ProtectedRoute>
                    <AppLayout />
                  </ProtectedRoute>
                }
              >
                <Route index element={<OverviewPage />} />
                <Route path="scanner" element={<FileScannerPage />} />
                <Route path="scans/:scanId" element={<ScanResultPage />} />
                <Route path="monitoring" element={<LiveMonitoringPage />} />
                <Route path="history" element={<ScanHistoryPage />} />
                <Route path="threat-intel" element={<ThreatIntelPage />} />
                <Route path="datasets" element={<DatasetManagerPage />} />
                <Route path="models" element={<ModelAnalyticsPage />} />
                <Route path="reports" element={<ReportsPage />} />
                <Route path="notifications" element={<NotificationsPage />} />
                <Route path="settings" element={<SettingsPage />} />

                <Route
                  path="admin"
                  element={
                    <AdminRoute>
                      <AdminPanelPage />
                    </AdminRoute>
                  }
                />
                <Route
                  path="admin/users"
                  element={
                    <AdminRoute>
                      <UserManagementPage />
                    </AdminRoute>
                  }
                />
                <Route
                  path="admin/training"
                  element={
                    <AdminRoute>
                      <ModelTrainingPage />
                    </AdminRoute>
                  }
                />
                <Route
                  path="admin/logs"
                  element={
                    <AdminRoute>
                      <SystemLogsPage />
                    </AdminRoute>
                  }
                />
              </Route>
            </Routes>
          </BrowserRouter>
        </AuthProvider>
      </ToastProvider>
    </QueryClientProvider>
  );
}

export default App;
