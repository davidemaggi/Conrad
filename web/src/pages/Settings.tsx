import { useEffect, useState } from "react";
import { useSearchParams } from "react-router";
import { useTranslation } from "react-i18next";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Download, Monitor, Moon, Sun } from "lucide-react";
import { api, setCsrf } from "@/lib/api";
import type { Admin, AuthSettings, Me, SystemInfo } from "@/lib/types";
import { LANGUAGES } from "@/i18n";
import { useTheme } from "@/lib/theme";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { Input, PasswordInput } from "@/components/ui/input";
import { Field, FieldLabel } from "@/components/ui/field";
import { Select } from "@/components/ui/select";
import { Switch, Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/misc";
import { CopyButton, ErrorAlert, KV, LoadingRows, PageHeader, Section } from "@/components/common";
import { cn, fmtDate } from "@/lib/utils";
import { useTitle } from "@/App";

function Profile({ me }: { me: Me }) {
  const { t, i18n } = useTranslation();
  const qc = useQueryClient();
  const { theme, setTheme } = useTheme();
  const [username, setUsername] = useState(me.admin.username);
  const m = useMutation({
    mutationFn: (body: Partial<Admin>) => api.put<Admin>("/auth/profile", body),
    onSuccess: async () => { toast.success(t("common.saved")); await qc.invalidateQueries({ queryKey: ["me"] }); },
  });
  const themes = [
    { v: "light", icon: Sun },
    { v: "dark", icon: Moon },
    { v: "system", icon: Monitor },
  ] as const;
  return (
    <Card><CardContent className="pt-6">
      <Section title={t("settings.account")} description={t("settings.accountText")}>
        <form className="grid max-w-md gap-4" onSubmit={(e) => { e.preventDefault(); m.mutate({ username }); }}>
          <Field label={t("auth.username")} required>
            <Input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" />
          </Field>
          <ErrorAlert error={m.error} />
          <div><Button type="submit" loading={m.isPending} disabled={!username.trim() || username === me.admin.username}>{t("common.save")}</Button></div>
        </form>
      </Section>
      <Section title={t("prefs.language")} description={t("settings.languageText")}>
        <div className="max-w-xs">
          <Select
            aria-label={t("prefs.language")}
            value={i18n.resolvedLanguage ?? "en"}
            onValueChange={(v) => { void i18n.changeLanguage(v); m.mutate({ language: v }); }}
            options={LANGUAGES.map((l) => ({ value: l.code, label: l.label }))}
          />
        </div>
      </Section>
      <Section title={t("prefs.theme")} description={t("settings.themeText")}>
        <div role="radiogroup" aria-label={t("prefs.theme")} className="grid max-w-md grid-cols-3 gap-2">
          {themes.map(({ v, icon: Icon }) => (
            <button
              key={v}
              type="button"
              role="radio"
              aria-checked={theme === v}
              onClick={() => setTheme(v)}
              className={cn("flex flex-col items-center gap-2 rounded-lg border p-4 text-sm transition-colors hover:bg-muted", theme === v && "border-primary bg-primary/5 ring-1 ring-primary")}
            >
              <Icon className="size-5" aria-hidden />
              {t(`prefs.${v}`)}
            </button>
          ))}
        </div>
      </Section>
    </CardContent></Card>
  );
}

function Password() {
  const { t } = useTranslation();
  const [f, setF] = useState({ current: "", new: "", confirm: "" });
  const mismatch = f.confirm !== "" && f.confirm !== f.new;
  const m = useMutation({
    mutationFn: () => api.put<{ csrfToken: string }>("/auth/password", { current: f.current, new: f.new }),
    onSuccess: (d) => { setCsrf(d.csrfToken); setF({ current: "", new: "", confirm: "" }); toast.success(t("settings.passwordChanged")); },
  });
  return (
    <Card><CardContent className="pt-6">
      <Section title={t("settings.password")} description={t("settings.passwordText")}>
        <form className="grid max-w-md gap-4" onSubmit={(e) => { e.preventDefault(); if (!mismatch) m.mutate(); }}>
          <Field label={t("settings.currentPassword")} required>
            <PasswordInput value={f.current} onChange={(e) => setF({ ...f, current: e.target.value })} autoComplete="current-password" />
          </Field>
          <Field label={t("settings.newPassword")} hint={t("setup.passwordHint")} required>
            <PasswordInput value={f.new} onChange={(e) => setF({ ...f, new: e.target.value })} autoComplete="new-password" minLength={12} />
          </Field>
          <Field label={t("setup.confirmPassword")} error={mismatch ? t("setup.errors.mismatch") : undefined} required>
            <PasswordInput value={f.confirm} onChange={(e) => setF({ ...f, confirm: e.target.value })} autoComplete="new-password" />
          </Field>
          <ErrorAlert error={m.error} />
          <div><Button type="submit" loading={m.isPending} disabled={!f.current || !f.new || mismatch}>{t("settings.changePassword")}</Button></div>
        </form>
      </Section>
    </CardContent></Card>
  );
}

function AuthTab() {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["settings-auth"], queryFn: () => api.get<AuthSettings>("/settings/auth") });
  const [s, setS] = useState<AuthSettings | null>(null);
  useEffect(() => { if (q.data) setS({ ...q.data, oidc: { ...q.data.oidc, clientSecret: "" } }); }, [q.data]);
  const m = useMutation({
    mutationFn: (v: AuthSettings) => api.put<AuthSettings>("/settings/auth", { passwordLoginEnabled: v.passwordLoginEnabled, oidc: v.oidc }),
    onSuccess: async (d) => { toast.success(t("common.saved")); qc.setQueryData(["settings-auth"], d); await qc.invalidateQueries({ queryKey: ["status"] }); },
  });
  if (q.error) return <ErrorAlert error={q.error} onRetry={() => void q.refetch()} />;
  if (!s) return <LoadingRows rows={4} />;
  const o = s.oidc;
  const setO = (p: Partial<AuthSettings["oidc"]>) => setS({ ...s, oidc: { ...o, ...p } });
  return (
    <Card><CardContent className="pt-6">
      <form onSubmit={(e) => { e.preventDefault(); m.mutate(s); }}>
        <Section title={t("settings.oidc")} description={t("settings.oidcText")}>
          <div className="grid max-w-xl gap-4">
            <div className="flex items-center justify-between gap-4 rounded-lg border px-4 py-3">
              <FieldLabel htmlFor="oidc-on">{t("settings.oidcEnabled")}</FieldLabel>
              <Switch id="oidc-on" checked={o.enabled} onCheckedChange={(v) => setO({ enabled: v })} />
            </div>
            <Field label={t("settings.redirectUrl")} hint={t("settings.redirectUrlHint")}>
              <div className="flex items-center gap-1 rounded-md border bg-muted/40 py-1 pl-3 pr-1">
                <code className="min-w-0 flex-1 break-all font-mono text-[13px]">{s.oidcRedirectUrl}</code>
                <CopyButton value={s.oidcRedirectUrl ?? ""} />
              </div>
            </Field>
            <Field label={t("settings.issuerUrl")} required={o.enabled}>
              <Input type="url" value={o.issuer} onChange={(e) => setO({ issuer: e.target.value })} placeholder="https://auth.home.lab/application/o/conrad/" />
            </Field>
            <div className="grid gap-4 sm:grid-cols-2">
              <Field label={t("settings.clientId")} required={o.enabled}>
                <Input value={o.clientId} onChange={(e) => setO({ clientId: e.target.value })} autoComplete="off" />
              </Field>
              <Field label={t("settings.clientSecret")} hint={s.oidcClientSecretSet ? t("settings.secretKept") : undefined}>
                <PasswordInput value={o.clientSecret ?? ""} onChange={(e) => setO({ clientSecret: e.target.value })} autoComplete="new-password" placeholder={s.oidcClientSecretSet ? "••••••••" : ""} />
              </Field>
              <Field label={t("settings.allowedEmail")} hint={t("settings.allowedHint")}>
                <Input type="email" value={o.allowedEmail} onChange={(e) => setO({ allowedEmail: e.target.value })} />
              </Field>
              <Field label={t("settings.allowedSubject")}>
                <Input value={o.allowedSubject} onChange={(e) => setO({ allowedSubject: e.target.value })} className="font-mono" />
              </Field>
            </div>
          </div>
        </Section>
        <Section title={t("settings.passwordLogin")} description={t("settings.passwordLoginText")}>
          <div className="flex max-w-xl items-center justify-between gap-4 rounded-lg border px-4 py-3">
            <FieldLabel htmlFor="pw-on">{t("settings.passwordLoginEnabled")}</FieldLabel>
            <Switch id="pw-on" checked={s.passwordLoginEnabled} onCheckedChange={(v) => setS({ ...s, passwordLoginEnabled: v })} />
          </div>
          {!s.passwordLoginEnabled && <p className="mt-2 max-w-xl text-sm text-warning">{t("settings.passwordLoginWarning")}</p>}
        </Section>
        <div className="flex justify-end gap-2 border-t pt-4">
          <ErrorAlert error={m.error} className="mr-auto" />
          <Button type="submit" loading={m.isPending}>{t("common.save")}</Button>
        </div>
      </form>
    </CardContent></Card>
  );
}

function SystemTab() {
  const { t } = useTranslation();
  const q = useQuery({ queryKey: ["system-info"], queryFn: () => api.get<SystemInfo>("/system/info") });
  const i = q.data;
  const uptime = (s: number) => {
    const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
    return [d && `${d}d`, (d || h) && `${h}h`, `${m}m`].filter(Boolean).join(" ");
  };
  return (
    <Card><CardContent className="pt-6">
      <Section title={t("settings.system")} description={t("settings.systemText")}>
        <ErrorAlert error={q.error} onRetry={() => void q.refetch()} />
        {!i ? <LoadingRows rows={4} /> : (
          <KV items={[
            [t("settings.version"), <code className="font-mono text-[13px]">{i.version}</code>],
            [t("settings.baseUrl"), <code className="font-mono text-[13px]">{i.baseUrl}</code>],
            [t("settings.dataDir"), <code className="font-mono text-[13px]">{i.dataDir}</code>],
            [t("settings.keyProvider"), <span className="flex flex-wrap gap-2"><Badge variant="outline">{i.keyProvider}</Badge>{i.caLocked ? <Badge variant="warning">{t("settings.locked")}</Badge> : <Badge variant="success">{t("settings.unlocked")}</Badge>}</span>],
            [t("settings.runtime"), `${i.goVersion} · ${i.os}`],
            [t("settings.uptime"), <span title={fmtDate(i.startedAt, true)}>{uptime(i.uptimeSec)}</span>],
          ]} />
        )}
      </Section>
      <Section title={t("settings.backup")} description={t("settings.backupText")}>
        <Button asChild variant="outline"><a href="/api/v1/system/backup" download><Download aria-hidden /> {t("settings.downloadBackup")}</a></Button>
        <p className="mt-3 max-w-xl text-sm text-muted-foreground">{t("settings.backupNote")}</p>
      </Section>
    </CardContent></Card>
  );
}

export default function Settings({ me }: { me?: Me }) {
  const { t } = useTranslation();
  useTitle(t("nav.settings"));
  const [params, setParams] = useSearchParams();
  const tab = params.get("tab") ?? "profile";
  return (
    <>
      <PageHeader eyebrow={t("nav.groups.system")} title={t("nav.settings")} description={t("settings.description")} />
      <Tabs value={tab} onValueChange={(v) => setParams(v === "profile" ? {} : { tab: v }, { replace: true })}>
        <TabsList>
          <TabsTrigger value="profile">{t("settings.profile")}</TabsTrigger>
          {me?.method === "password" || !me ? <TabsTrigger value="password">{t("settings.password")}</TabsTrigger> : null}
          <TabsTrigger value="auth">{t("settings.authentication")}</TabsTrigger>
          <TabsTrigger value="system">{t("settings.system")}</TabsTrigger>
        </TabsList>
        <TabsContent value="profile">{me ? <Profile me={me} /> : <LoadingRows />}</TabsContent>
        <TabsContent value="password"><Password /></TabsContent>
        <TabsContent value="auth"><AuthTab /></TabsContent>
        <TabsContent value="system"><SystemTab /></TabsContent>
      </Tabs>
    </>
  );
}
