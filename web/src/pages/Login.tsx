import { useEffect, useState } from "react";
import { useSearchParams } from "react-router";
import { useTranslation } from "react-i18next";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { KeyRound } from "lucide-react";
import { api, ApiError, setCsrf } from "@/lib/api";
import type { SystemStatus } from "@/lib/types";
import { AuthLayout } from "@/components/AuthLayout";
import { Button } from "@/components/ui/button";
import { Input, PasswordInput } from "@/components/ui/input";
import { Field } from "@/components/ui/field";
import { ErrorAlert } from "@/components/common";
import { useTitle } from "@/App";

export default function Login({ status }: { status: SystemStatus }) {
  const { t } = useTranslation();
  useTitle(t("auth.signIn"));
  const qc = useQueryClient();
  const [params] = useSearchParams();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [wait, setWait] = useState(0);
  const oidcError = params.get("error");

  const m = useMutation({
    mutationFn: () => api.post<{ csrfToken: string }>("/auth/login", { username, password }),
    onSuccess: async (r) => {
      setCsrf(r.csrfToken);
      await qc.invalidateQueries({ queryKey: ["status"] });
      window.history.replaceState(null, "", "/");
    },
    onError: (e) => {
      if (e instanceof ApiError && e.code === "auth.throttled") setWait(Number(e.details.retryAfter) || 5);
    },
  });

  useEffect(() => {
    if (wait <= 0) return;
    const id = setTimeout(() => setWait((w) => w - 1), 1000);
    return () => clearTimeout(id);
  }, [wait]);

  return (
    <AuthLayout>
      <h1 className="text-2xl font-semibold tracking-tight">{t("auth.signIn")}</h1>
      <p className="mt-1.5 text-sm text-muted-foreground">{t("auth.signInText")}</p>
      {oidcError && <ErrorAlert className="mt-6" error={new Error(t(`auth.oidcErrors.${oidcError}`, { defaultValue: t("auth.oidcErrors.generic") }))} />}
      {status.passwordLogin && (
        <form
          className="mt-6 grid gap-4"
          onSubmit={(e) => {
            e.preventDefault();
            m.mutate();
          }}
        >
          <Field label={t("auth.username")} required>
            <Input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" autoCapitalize="none" spellCheck={false} autoFocus />
          </Field>
          <Field label={t("auth.password")} required>
            <PasswordInput value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" />
          </Field>
          {m.isError && !(m.error instanceof ApiError && m.error.code === "auth.throttled" && wait > 0) && <ErrorAlert error={m.error} />}
          {wait > 0 && (
            <p role="status" className="text-sm text-warning">{t("auth.throttledWait", { count: wait })}</p>
          )}
          <Button type="submit" size="lg" loading={m.isPending} disabled={wait > 0 || !username || !password}>
            {t("auth.signIn")}
          </Button>
        </form>
      )}
      {status.oidcEnabled && (
        <>
          {status.passwordLogin && (
            <div className="my-6 flex items-center gap-3 text-xs uppercase tracking-[0.14em] text-muted-foreground">
              <span className="h-px flex-1 bg-border" /> {t("common.or")} <span className="h-px flex-1 bg-border" />
            </div>
          )}
          <Button asChild variant="outline" size="lg" className={status.passwordLogin ? "" : "mt-6"}>
            <a href="/api/v1/auth/oidc/start"><KeyRound aria-hidden /> {t("auth.signInOidc")}</a>
          </Button>
        </>
      )}
      {!status.passwordLogin && !status.oidcEnabled && <ErrorAlert className="mt-6" error={new Error(t("auth.noMethod"))} />}
    </AuthLayout>
  );
}
