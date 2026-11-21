import { useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router";
import { useTranslation } from "react-i18next";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Building2, ChevronRight, Landmark, Plus, RefreshCcw } from "lucide-react";
import { api } from "@/lib/api";
import type { Authority } from "@/lib/types";
import { CA_ALGORITHMS } from "@/lib/types";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card } from "@/components/ui/card";
import { Input, Textarea } from "@/components/ui/input";
import { Field, FieldLabel } from "@/components/ui/field";
import { Select } from "@/components/ui/select";
import { Switch } from "@/components/ui/misc";
import { Dialog, DialogContent, DialogFooter, DialogHeader } from "@/components/ui/dialog";
import { AuthorityStatusBadge, ConfirmDialog, CopyButton, ErrorAlert, Expiry, LoadingRows, PageHeader } from "@/components/common";
import { lines } from "@/components/PolicyForm";
import { cn, fmtNumber, validSlug } from "@/lib/utils";
import { useTitle } from "@/App";

export function useAuthorities() {
  return useQuery({ queryKey: ["authorities"], queryFn: () => api.get<{ items: Authority[] }>("/authorities"), select: (d) => d.items });
}

function Row({ a, depth }: { a: Authority; depth: number }) {
  const { t } = useTranslation();
  const Icon = a.kind === "root" ? Landmark : Building2;
  return (
    <li className={cn("relative", depth > 0 && "ml-6 border-l pl-4 sm:ml-8 sm:pl-6")}>
      <div className={cn("group flex flex-wrap items-center gap-x-4 gap-y-2 py-3 pr-2", a.status !== "active" && "opacity-70")}>
        <span className={cn("flex size-9 shrink-0 items-center justify-center rounded-lg", a.kind === "root" ? "bg-ink/10 text-ink" : "bg-primary/10 text-primary")}>
          <Icon className="size-[18px]" aria-hidden />
        </span>
        <div className="min-w-0 flex-1">
          <Link to={`/authorities/${a.id}`} className="flex flex-wrap items-center gap-2 font-medium hover:underline">
            {a.name}
            {a.kind === "root" ? <Badge variant="stamp" className="text-ink">{t("authorities.root")}</Badge> : <code className="font-mono text-xs font-normal text-muted-foreground">{a.slug}</code>}
            {a.isDefault && <Badge variant="info">{t("authorities.default")}</Badge>}
          </Link>
          {a.kind === "intermediate" && a.status === "active" ? (
            <div className="mt-0.5 flex min-w-0 items-center gap-1">
              <code className="truncate font-mono text-xs text-muted-foreground">{a.directoryUrl}</code>
              <CopyButton value={a.directoryUrl} label={t("authorities.copyDirectory")} className="size-7" />
            </div>
          ) : (
            <p className="mt-0.5 text-xs text-muted-foreground"><span className="font-mono">{a.subject}</span> · {a.algorithm}</p>
          )}
        </div>
        {a.kind === "intermediate" && (
          <span className="text-sm text-muted-foreground tabular">{t("authorities.certCount", { count: a.activeCertificates, n: fmtNumber(a.activeCertificates) })}</span>
        )}
        <span className="text-sm"><Expiry value={a.notAfter} warnDays={90} /></span>
        <AuthorityStatusBadge status={a.status} />
        <Button asChild variant="ghost" size="icon-sm" aria-label={t("common.details")}>
          <Link to={`/authorities/${a.id}`}><ChevronRight aria-hidden /></Link>
        </Button>
      </div>
    </li>
  );
}

export function CreateIssuerDialog({ open, onOpenChange, authorities }: { open: boolean; onOpenChange: (o: boolean) => void; authorities: Authority[] }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const nav = useNavigate();
  const issuers = authorities.filter((a) => a.kind === "intermediate" && a.status === "active");
  const [f, setF] = useState({ slug: "", name: "", description: "", algorithm: "ecdsa-p256", validityYears: 5, nameConstraints: "", default: false, clonePolicyFrom: issuers.find((i) => i.isDefault)?.slug ?? "" });
  const [touched, setTouched] = useState(false);
  const slugErr = touched && !validSlug(f.slug) ? t("errors.issuer.invalid_slug") : undefined;
  const m = useMutation({
    mutationFn: () =>
      api.post<Authority>("/authorities", {
        ...f,
        name: f.name || f.slug,
        nameConstraints: lines(f.nameConstraints),
        subject: { commonName: f.name || f.slug, organization: "", country: "" },
        clonePolicyFrom: f.clonePolicyFrom === "-" ? "" : f.clonePolicyFrom,
      }),
    onSuccess: async (a) => {
      toast.success(t("authorities.created", { name: a.name }));
      await qc.invalidateQueries({ queryKey: ["authorities"] });
      onOpenChange(false);
      nav(`/authorities/${a.id}`);
    },
  });
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent wide>
        <DialogHeader title={t("authorities.create")} description={t("authorities.createText")} />
        <form
          className="grid gap-4 sm:grid-cols-2"
          noValidate
          onSubmit={(e) => {
            e.preventDefault();
            setTouched(true);
            if (validSlug(f.slug)) m.mutate();
          }}
        >
          <Field label={t("ca.slug")} hint={t("ca.slugHint")} error={slugErr} required>
            <Input value={f.slug} onChange={(e) => setF({ ...f, slug: e.target.value.toLowerCase() })} className="font-mono" placeholder="servers" autoFocus />
          </Field>
          <Field label={t("ca.name")}>
            <Input value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} placeholder="Servers Issuer" />
          </Field>
          <Field label={t("ca.description")} className="sm:col-span-2">
            <Input value={f.description} onChange={(e) => setF({ ...f, description: e.target.value })} />
          </Field>
          <Field label={t("ca.algorithm")}>
            <Select value={f.algorithm} onValueChange={(v) => setF({ ...f, algorithm: v })} options={CA_ALGORITHMS.map((a) => ({ value: a, label: a }))} />
          </Field>
          <Field label={t("ca.validityYears")}>
            <Input type="number" min={1} max={30} value={f.validityYears} onChange={(e) => setF({ ...f, validityYears: Number(e.target.value) })} />
          </Field>
          <Field label={t("authorities.clonePolicy")} hint={t("authorities.clonePolicyHint")}>
            <Select
              value={f.clonePolicyFrom || "-"}
              onValueChange={(v) => setF({ ...f, clonePolicyFrom: v })}
              options={[{ value: "-", label: t("authorities.defaultPolicy") }, ...issuers.map((i) => ({ value: i.slug, label: `${i.name} (${i.slug})` }))]}
            />
          </Field>
          <div className="flex items-center justify-between gap-4 rounded-lg border px-4 py-3 sm:self-end">
            <FieldLabel htmlFor="ci-default">{t("authorities.makeDefault")}</FieldLabel>
            <Switch id="ci-default" checked={f.default} onCheckedChange={(v) => setF({ ...f, default: v })} />
          </div>
          <Field label={t("ca.nameConstraints")} hint={t("ca.nameConstraintsHint")} className="sm:col-span-2">
            <Textarea rows={2} className="font-mono text-[13px]" value={f.nameConstraints} onChange={(e) => setF({ ...f, nameConstraints: e.target.value })} />
          </Field>
          <ErrorAlert error={m.error} className="sm:col-span-2" />
          <DialogFooter className="sm:col-span-2">
            <Button variant="outline" onClick={() => onOpenChange(false)}>{t("common.cancel")}</Button>
            <Button type="submit" loading={m.isPending}>{t("authorities.createAction")}</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

export default function Authorities() {
  const { t } = useTranslation();
  useTitle(t("nav.authorities"));
  const qc = useQueryClient();
  const [params, setParams] = useSearchParams();
  const q = useAuthorities();
  const [succ, setSucc] = useState(false);
  const createOpen = params.get("create") === "1";
  const setCreate = (o: boolean) => setParams(o ? { create: "1" } : {}, { replace: true });
  const successor = useMutation({
    mutationFn: () => api.post<Authority>("/authorities/successor-root", { validityYears: 20 }),
    onSuccess: async () => {
      setSucc(false);
      toast.success(t("authorities.successorCreated"));
      await qc.invalidateQueries({ queryKey: ["authorities"] });
    },
  });

  const all = q.data ?? [];
  const roots = all.filter((a) => a.kind === "root").sort((a, b) => (a.status === "active" ? -1 : 1) - (b.status === "active" ? -1 : 1) || b.notAfter.localeCompare(a.notAfter));
  const childrenOf = (id: string) => all.filter((a) => a.kind === "intermediate" && a.parentId === id).sort((a, b) => Number(b.isDefault) - Number(a.isDefault) || a.slug.localeCompare(b.slug));
  const orphans = all.filter((a) => a.kind === "intermediate" && !roots.some((r) => r.id === a.parentId));

  return (
    <>
      <PageHeader
        eyebrow={t("nav.groups.pki")}
        title={t("nav.authorities")}
        description={t("authorities.description")}
        actions={
          <>
            <Button variant="outline" onClick={() => setSucc(true)}><RefreshCcw aria-hidden /> {t("authorities.successor")}</Button>
            <Button onClick={() => setCreate(true)}><Plus aria-hidden /> {t("authorities.create")}</Button>
          </>
        }
      />
      <ErrorAlert error={q.error} onRetry={() => void q.refetch()} className="mb-4" />
      <Card className="px-4 py-2 sm:px-5">
        {q.isPending ? (
          <LoadingRows rows={3} />
        ) : (
          <ul className="divide-y">
            {roots.map((r) => (
              <li key={r.id}>
                <ul>
                  <Row a={r} depth={0} />
                  {childrenOf(r.id).map((c) => (
                    <Row key={c.id} a={c} depth={1} />
                  ))}
                </ul>
              </li>
            ))}
            {orphans.map((c) => (
              <Row key={c.id} a={c} depth={0} />
            ))}
          </ul>
        )}
      </Card>
      {q.data && <CreateIssuerDialog open={createOpen} onOpenChange={setCreate} authorities={all} />}
      <ConfirmDialog
        open={succ}
        onOpenChange={setSucc}
        title={t("authorities.successor")}
        description={t("authorities.successorText")}
        actionLabel={t("authorities.successorAction")}
        onConfirm={() => successor.mutate()}
        loading={successor.isPending}
        error={successor.error}
      />
    </>
  );
}
