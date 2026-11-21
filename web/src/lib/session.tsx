import { useEffect } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api, setCsrf } from "@/lib/api";
import type { Me, SystemStatus } from "@/lib/types";
import i18n from "@/i18n";

export function useStatus() {
  return useQuery({ queryKey: ["status"], queryFn: () => api.get<SystemStatus>("/system/status"), staleTime: 30_000 });
}

export function useMe(enabled: boolean) {
  const q = useQuery({
    queryKey: ["me"],
    enabled,
    queryFn: async () => {
      const me = await api.get<Me>("/auth/me");
      setCsrf(me.csrfToken);
      return me;
    },
    staleTime: 60_000,
  });
  useEffect(() => {
    const lang = q.data?.admin.language;
    if (lang && !localStorage.getItem("i18nextLng") && lang !== i18n.resolvedLanguage) void i18n.changeLanguage(lang);
  }, [q.data?.admin.language]);
  return q;
}

/** Re-checks status whenever the API reports a missing session. */
export function useUnauthorizedListener() {
  const qc = useQueryClient();
  useEffect(() => {
    const on = () => {
      qc.removeQueries({ queryKey: ["me"] });
      void qc.invalidateQueries({ queryKey: ["status"] });
    };
    window.addEventListener("conrad:unauthorized", on);
    return () => window.removeEventListener("conrad:unauthorized", on);
  }, [qc]);
}

export function useLogout() {
  const qc = useQueryClient();
  return async () => {
    try {
      await api.post("/auth/logout");
    } finally {
      qc.clear();
      await qc.invalidateQueries({ queryKey: ["status"] });
      window.location.assign("/login");
    }
  };
}
