import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { AlertTriangle, Mail, MoreHorizontal, Plus, Send, Trash2, Webhook, X } from "lucide-react";
import { api } from "@/lib/api";
import type { Channel, SMTPConfig } from "@/lib/types";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input, PasswordInput, Textarea } from "@/components/ui/input";
import { Field, FieldLabel } from "@/components/ui/field";
import { Select } from "@/components/ui/select";
import { Checkbox, DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger, Switch } from "@/components/ui/misc";
import { Dialog, DialogContent, DialogFooter, DialogHeader } from "@/components/ui/dialog";
import { ConfirmDialog, EmptyState, ErrorAlert, LoadingRows, PageHeader } from "@/components/common";
import { lines } from "@/components/PolicyForm";
import { cn } from "@/lib/utils";
import { useTitle } from "@/App";

type Kind = "smtp" | "webhook";
const DEFAULT_EVENTS = ["cert.expiring", "ca.expiring", "ca.locked", "acme.failed"];
const PORTS: Record<SMTPConfig["security"], number> = { none: 25, starttls: 587, tls: 465 };

interface Draft {
  id?: string;
  kind: Kind;
  name: string;
  enabled: boolean;
  events: string[];
  smtp: SMTPConfig & { toText: string };
  webhook: { url: string; secret: string };
  secretSet: boolean;
}

function toDraft(c?: Channel, kind: Kind = "smtp"): Draft {
  const s = c?.smtp;
  return {
    id: c?.id,
    kind: c?.kind ?? kind,
    name: c?.name ?? "",
    enabled: c?.enabled ?? true,
    events: c?.events ?? DEFAULT_EVENTS,
    smtp: {
      host: s?.host ?? "", port: s?.port ?? 587, security: s?.security ?? "starttls", username: s?.username ?? "", password: "",
      authMethod: s?.authMethod ?? "plain", skipVerify: s?.skipVerify ?? false, from: s?.from ?? "", to: s?.to ?? [], toText: (s?.to ?? []).join("\n"),
    },
    webhook: { url: c?.webhook?.url ?? "", secret: "" },
    secretSet: c?.secretSet ?? false,
  };
}

function toBody(d: Draft) {
  const { toText, ...smtp } = d.smtp;
  return {
    id: d.id,
    kind: d.kind,
    name: d.name,
    enabled: d.enabled,
    events: d.events,
    ...(d.kind === "smtp" ? { smtp: { ...smtp, to: lines(toText) } } : { webhook: d.webhook }),
  };
}

function ChannelDialog({ initial, events, open, onOpenChange }: { initial: Draft; events: string[]; open: boolean; onOpenChange: (o: boolean) => void }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const [d, setD] = useState(initial);
  useEffect(() => setD(initial), [initial]);
  const s = d.smtp;
  const setS = (p: Partial<Draft["smtp"]>) => setD({ ...d, smtp: { ...s, ...p } });
  const save = useMutation({
    mutationFn: () => (d.id ? api.put<Channel>(`/notifications/channels/${d.id}`, toBody(d)) : api.post<Channel>("/notifications/channels", toBody(d))),
    onSuccess: async () => { toast.success(t("common.saved")); await qc.invalidateQueries({ queryKey: ["channels"] }); onOpenChange(false); },
  });
  const test = useMutation({
    mutationFn: () => api.post("/notifications/test", toBody(d)),
    onSuccess: () => toast.success(t("notify.testSent")),
  });
  const plaintextCreds = d.kind === "smtp" && s.security === "none" && !!s.username;
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent wide>
        <DialogHeader title={d.id ? t("notify.editChannel") : t("notify.addChannel")} />
        <form className="grid gap-5" onSubmit={(e) => { e.preventDefault(); save.mutate(); }}>
          {!d.id && (
            <div role="radiogroup" aria-label={t("notify.kind")} className="grid grid-cols-2 gap-2">
              {(["smtp", "webhook"] as const).map((k) => {
                const Icon = k === "smtp" ? Mail : Webhook;
                return (
                  <button key={k} type="button" role="radio" aria-checked={d.kind === k} onClick={() => setD({ ...d, kind: k })}
                    className={cn("flex items-center gap-3 rounded-lg border p-3 text-left text-sm transition-colors hover:bg-muted", d.kind === k && "border-primary bg-primary/5 ring-1 ring-primary")}>
                    <Icon className="size-5 text-primary" aria-hidden />
                    <span><span className="block font-medium">{t(`notify.kinds.${k}`)}</span><span className="text-xs text-muted-foreground">{t(`notify.kinds.${k}Text`)}</span></span>
                  </button>
                );
              })}
            </div>
          )}
          <div className="grid gap-4 sm:grid-cols-[1fr_auto]">
            <Field label={t("ca.name")} required>
              <Input value={d.name} onChange={(e) => setD({ ...d, name: e.target.value })} placeholder={d.kind === "smtp" ? "Homelab mail" : "ntfy"} />
            </Field>
            <div className="flex items-center gap-3 sm:self-end sm:pb-2">
              <Switch id="ch-enabled" checked={d.enabled} onCheckedChange={(v) => setD({ ...d, enabled: v })} />
              <FieldLabel htmlFor="ch-enabled">{t("notify.enabled")}</FieldLabel>
            </div>
          </div>

          {d.kind === "smtp" ? (
            <fieldset className="grid gap-4 sm:grid-cols-6">
              <legend className="sr-only">SMTP</legend>
              <Field label={t("notify.host")} required className="sm:col-span-3">
                <Input value={s.host} onChange={(e) => setS({ host: e.target.value })} placeholder="mail.home.lab" autoComplete="off" />
              </Field>
              <Field label={t("notify.security")} className="sm:col-span-2">
                <Select
                  value={s.security}
                  onValueChange={(v) => {
                    const sec = v as SMTPConfig["security"];
                    setS({ security: sec, port: Object.values(PORTS).includes(s.port) ? PORTS[sec] : s.port });
                  }}
                  options={(["none", "starttls", "tls"] as const).map((v) => ({ value: v, label: t(`notify.securityModes.${v}`) }))}
                />
              </Field>
              <Field label={t("notify.port")} className="sm:col-span-1">
                <Input type="number" min={1} max={65535} value={s.port} onChange={(e) => setS({ port: Number(e.target.value) })} />
              </Field>
              <Field label={t("notify.username")} hint={t("notify.usernameHint")} className="sm:col-span-2">
                <Input value={s.username} onChange={(e) => setS({ username: e.target.value })} autoComplete="off" />
              </Field>
              <Field label={t("notify.password")} hint={d.secretSet && s.username ? t("settings.secretKept") : undefined} className="sm:col-span-2">
                <PasswordInput value={s.password ?? ""} onChange={(e) => setS({ password: e.target.value })} disabled={!s.username} autoComplete="new-password" placeholder={d.secretSet && s.username ? "••••••••" : ""} />
              </Field>
              <Field label={t("notify.authMethod")} className="sm:col-span-2">
                <Select value={s.authMethod} disabled={!s.username} onValueChange={(v) => setS({ authMethod: v as SMTPConfig["authMethod"] })} options={[{ value: "plain", label: "PLAIN" }, { value: "login", label: "LOGIN" }]} />
              </Field>
              {plaintextCreds && (
                <p role="alert" className="flex items-start gap-2 rounded-md border border-warning/40 bg-warning-fill px-3 py-2 text-sm sm:col-span-6">
                  <AlertTriangle className="mt-0.5 size-4 shrink-0 text-warning" aria-hidden /> {t("notify.plaintextWarning")}
                </p>
              )}
              <Field label={t("notify.from")} required className="sm:col-span-3">
                <Input type="email" value={s.from} onChange={(e) => setS({ from: e.target.value })} placeholder="conrad@home.lab" />
              </Field>
              <Field label={t("notify.to")} hint={t("notify.toHint")} required className="sm:col-span-3">
                <Textarea rows={2} value={s.toText} onChange={(e) => setS({ toText: e.target.value })} placeholder="me@example.com" />
              </Field>
              {s.security !== "none" && (
                <div className="flex items-center gap-3 sm:col-span-6">
                  <Checkbox id="ch-skip" checked={s.skipVerify} onCheckedChange={(v) => setS({ skipVerify: v === true })} />
                  <FieldLabel htmlFor="ch-skip" className="font-normal">{t("notify.skipVerify")}</FieldLabel>
                </div>
              )}
            </fieldset>
          ) : (
            <div className="grid gap-4">
              <Field label="URL" required>
                <Input type="url" value={d.webhook.url} onChange={(e) => setD({ ...d, webhook: { ...d.webhook, url: e.target.value } })} placeholder="https://ntfy.home.lab/conrad" />
              </Field>
              <Field label={t("notify.secret")} hint={d.secretSet ? t("settings.secretKept") : t("notify.secretHint")}>
                <PasswordInput value={d.webhook.secret} onChange={(e) => setD({ ...d, webhook: { ...d.webhook, secret: e.target.value } })} autoComplete="new-password" placeholder={d.secretSet ? "••••••••" : ""} />
              </Field>
            </div>
          )}

          <fieldset>
            <legend className="mb-2 text-sm font-medium">{t("notify.events")}</legend>
            <div className="grid gap-2 sm:grid-cols-2">
              {events.map((ev) => (
                <label key={ev} className="flex cursor-pointer items-start gap-3 rounded-md border px-3 py-2 hover:bg-muted/50">
                  <Checkbox
                    className="mt-0.5"
                    checked={d.events.includes(ev)}
                    onCheckedChange={(v) => setD({ ...d, events: v === true ? [...d.events, ev] : d.events.filter((x) => x !== ev) })}
                  />
                  <span className="text-sm">
                    <span className="block font-medium">{t(`notify.eventNames.${ev.replace(".", "_")}`)}</span>
                    <span className="text-xs text-muted-foreground">{t(`notify.eventHints.${ev.replace(".", "_")}`)}</span>
                  </span>
                </label>
              ))}
            </div>
          </fieldset>

          <ErrorAlert error={save.error ?? test.error} />
          <DialogFooter className="sm:justify-between">
            <Button variant="outline" onClick={() => test.mutate()} loading={test.isPending}><Send aria-hidden /> {t("notify.sendTest")}</Button>
            <div className="flex flex-col-reverse gap-2 sm:flex-row">
              <Button variant="ghost" onClick={() => onOpenChange(false)}>{t("common.cancel")}</Button>
              <Button type="submit" loading={save.isPending} disabled={!d.name.trim()}>{t("common.save")}</Button>
            </div>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function Thresholds() {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["notify-settings"], queryFn: () => api.get<{ thresholdsDays: number[] }>("/notifications/settings") });
  const [list, setList] = useState<number[]>([]);
  const [add, setAdd] = useState("");
  useEffect(() => { if (q.data) setList(q.data.thresholdsDays); }, [q.data]);
  const m = useMutation({
    mutationFn: (v: number[]) => api.put<{ thresholdsDays: number[] }>("/notifications/settings", { thresholdsDays: v }),
    onSuccess: (d) => { qc.setQueryData(["notify-settings"], d); toast.success(t("common.saved")); },
  });
  const n = Number(add);
  const canAdd = Number.isInteger(n) && n >= 1 && n <= 365 && !list.includes(n) && list.length < 10;
  const dirty = JSON.stringify([...list].sort((a, b) => b - a)) !== JSON.stringify(q.data?.thresholdsDays);
  return (
    <Card>
      <CardHeader>
        <CardTitle>{t("notify.thresholds")}</CardTitle>
        <CardDescription>{t("notify.thresholdsText")}</CardDescription>
      </CardHeader>
      <CardContent className="grid gap-4">
        <ul className="flex flex-wrap gap-2" aria-label={t("notify.thresholds")}>
          {[...list].sort((a, b) => b - a).map((d) => (
            <li key={d}>
              <span className="inline-flex items-center gap-1 rounded-full border bg-muted/50 py-1 pl-3 pr-1 text-sm tabular">
                {t("notify.daysBefore", { count: d })}
                <button type="button" className="rounded-full p-1 hover:bg-muted" onClick={() => setList(list.filter((x) => x !== d))} disabled={list.length <= 1} aria-label={t("notify.removeThreshold", { count: d })}>
                  <X className="size-3.5" aria-hidden />
                </button>
              </span>
            </li>
          ))}
        </ul>
        <form className="flex flex-wrap items-end gap-2" onSubmit={(e) => { e.preventDefault(); if (canAdd) { setList([...list, n]); setAdd(""); } }}>
          <Field label={t("notify.addThreshold")} className="w-36">
            <Input type="number" min={1} max={365} value={add} onChange={(e) => setAdd(e.target.value)} placeholder="60" />
          </Field>
          <Button type="submit" variant="outline" disabled={!canAdd}><Plus aria-hidden /> {t("common.add")}</Button>
          <Button type="button" className="ml-auto" disabled={!dirty} loading={m.isPending} onClick={() => m.mutate(list)}>{t("common.save")}</Button>
        </form>
        <p className="text-xs text-muted-foreground">{t("notify.caThresholds")}</p>
        <ErrorAlert error={m.error ?? q.error} />
      </CardContent>
    </Card>
  );
}

export default function Notifications() {
  const { t } = useTranslation();
  useTitle(t("nav.notifications"));
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["channels"], queryFn: () => api.get<{ items: Channel[]; events: string[] }>("/notifications/channels") });
  const [editing, setEditing] = useState<Draft | null>(null);
  const [deleting, setDeleting] = useState<Channel | null>(null);
  const test = useMutation({
    mutationFn: (c: Channel) => api.post(`/notifications/channels/${c.id}/test`, {}),
    onSuccess: () => toast.success(t("notify.testSent")),
    onError: (e) => toast.error(e instanceof Error ? e.message : String(e)),
  });
  const toggle = useMutation({
    mutationFn: (c: Channel) => api.put(`/notifications/channels/${c.id}`, { ...c, enabled: !c.enabled }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["channels"] }),
  });
  const del = useMutation({
    mutationFn: (c: Channel) => api.del(`/notifications/channels/${c.id}`),
    onSuccess: async () => { setDeleting(null); toast.success(t("notify.deleted")); await qc.invalidateQueries({ queryKey: ["channels"] }); },
  });
  const events = q.data?.events ?? DEFAULT_EVENTS;
  return (
    <>
      <PageHeader
        eyebrow={t("nav.groups.system")}
        title={t("nav.notifications")}
        description={t("notify.description")}
        actions={<Button onClick={() => setEditing(toDraft())}><Plus aria-hidden /> {t("notify.addChannel")}</Button>}
      />
      <div className="grid gap-6 lg:grid-cols-[1fr_22rem]">
        <div className="grid content-start gap-3">
          <ErrorAlert error={q.error ?? toggle.error} onRetry={() => void q.refetch()} />
          {q.isPending ? <Card className="p-6"><LoadingRows rows={3} /></Card> : !q.data?.items.length ? (
            <Card>
              <EmptyState
                title={t("notify.empty")}
                description={t("notify.emptyText")}
                action={<Button onClick={() => setEditing(toDraft())}><Plus aria-hidden /> {t("notify.addChannel")}</Button>}
                className="py-12"
              />
            </Card>
          ) : (
            q.data.items.map((c) => {
              const Icon = c.kind === "smtp" ? Mail : Webhook;
              const dest = c.kind === "smtp" ? `${c.smtp?.host}:${c.smtp?.port} → ${c.smtp?.to.join(", ")}` : c.webhook?.url;
              return (
                <Card key={c.id} className={cn("flex items-center gap-4 p-4", !c.enabled && "opacity-70")}>
                  <span className="flex size-10 shrink-0 items-center justify-center rounded-lg bg-primary/10 text-primary"><Icon className="size-5" aria-hidden /></span>
                  <div className="min-w-0 flex-1">
                    <p className="flex flex-wrap items-center gap-2 font-medium">
                      {c.name}
                      {c.kind === "smtp" && <Badge variant="outline">{t(`notify.securityModes.${c.smtp?.security}`)}</Badge>}
                      {!c.enabled && <Badge variant="outline">{t("notify.disabled")}</Badge>}
                    </p>
                    <p className="truncate font-mono text-xs text-muted-foreground" title={dest}>{dest}</p>
                    <p className="mt-1 text-xs text-muted-foreground">{t("notify.eventCount", { count: c.events.length })}</p>
                  </div>
                  <Switch checked={c.enabled} onCheckedChange={() => toggle.mutate(c)} aria-label={t("notify.enabled")} />
                  <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                      <Button variant="ghost" size="icon-sm" aria-label={t("common.actions")}><MoreHorizontal aria-hidden /></Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="end">
                      <DropdownMenuItem onSelect={() => setEditing(toDraft(c))}>{t("common.edit")}</DropdownMenuItem>
                      <DropdownMenuItem onSelect={() => test.mutate(c)}><Send aria-hidden /> {t("notify.sendTest")}</DropdownMenuItem>
                      <DropdownMenuSeparator />
                      <DropdownMenuItem className="text-destructive" onSelect={() => setDeleting(c)}><Trash2 aria-hidden /> {t("common.delete")}</DropdownMenuItem>
                    </DropdownMenuContent>
                  </DropdownMenu>
                </Card>
              );
            })
          )}
        </div>
        <Thresholds />
      </div>
      {editing && <ChannelDialog initial={editing} events={events} open onOpenChange={(o) => !o && setEditing(null)} />}
      <ConfirmDialog
        open={!!deleting}
        onOpenChange={(o) => !o && setDeleting(null)}
        title={t("notify.deleteTitle")}
        description={t("notify.deleteText", { name: deleting?.name })}
        actionLabel={t("common.delete")}
        destructive
        onConfirm={() => deleting && del.mutate(deleting)}
        loading={del.isPending}
        error={del.error}
      />
    </>
  );
}
