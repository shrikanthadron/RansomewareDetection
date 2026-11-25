import React, { createContext, useCallback, useContext, useEffect, useState } from "react";
import { api } from "./api";
import type { TokenResponse, User } from "./types";

interface AuthContextValue {
  user: User | null;
  token: string | null;
  loading: boolean;
  login: (email: string, password: string) => Promise<User>;
  register: (fullName: string, email: string, password: string) => Promise<User>;
  logout: () => Promise<void>;
  refreshUser: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [token, setToken] = useState<string | null>(() => localStorage.getItem("rs_token"));
  const [user, setUser] = useState<User | null>(() => {
    const raw = localStorage.getItem("rs_user");
    try {
      return raw ? (JSON.parse(raw) as User) : null;
    } catch {
      return null;
    }
  });
  const [loading, setLoading] = useState<boolean>(!!token);

  const applyTheme = (u: User | null) => {
    const theme = (u?.preferences?.theme as string) || localStorage.getItem("rs_theme") || "dark";
    const root = document.documentElement;
    if (theme === "light") {
      root.classList.remove("dark");
      root.classList.add("light");
    } else {
      root.classList.remove("light");
      root.classList.add("dark");
    }
  };

  const refreshUser = useCallback(async () => {
    const t = localStorage.getItem("rs_token");
    if (!t) {
      setLoading(false);
      return;
    }
    try {
      const { data } = await api.get<User>("/api/auth/me");
      setUser(data);
      localStorage.setItem("rs_user", JSON.stringify(data));
      applyTheme(data);
    } catch {
      localStorage.removeItem("rs_token");
      localStorage.removeItem("rs_user");
      setToken(null);
      setUser(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    applyTheme(user);
    if (token) {
      refreshUser();
    } else {
      setLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const login = async (email: string, password: string): Promise<User> => {
    const { data } = await api.post<TokenResponse>("/api/auth/login", { email, password });
    localStorage.setItem("rs_token", data.access_token);
    localStorage.setItem("rs_user", JSON.stringify(data.user));
    setToken(data.access_token);
    setUser(data.user);
    applyTheme(data.user);
    return data.user;
  };

  const register = async (fullName: string, email: string, password: string): Promise<User> => {
    const { data } = await api.post<TokenResponse>("/api/auth/register", {
      full_name: fullName,
      email,
      password,
    });
    localStorage.setItem("rs_token", data.access_token);
    localStorage.setItem("rs_user", JSON.stringify(data.user));
    setToken(data.access_token);
    setUser(data.user);
    applyTheme(data.user);
    return data.user;
  };

  const logout = async () => {
    try {
      await api.post("/api/auth/logout");
    } catch {
      // Ignore network errors on logout
    }
    localStorage.removeItem("rs_token");
    localStorage.removeItem("rs_user");
    setToken(null);
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ user, token, loading, login, register, logout, refreshUser }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used inside AuthProvider");
  return ctx;
}
