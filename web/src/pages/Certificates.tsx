import { useState } from "react";
import { Link, useSearchParams } from "react-router";
import { useTranslation } from "react-i18next";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Download, FileBadge, Plus, Search } from "lucide-react";
import { api, qs } from "@/lib/api";
import type { Certificate } from "@/lib/types";
import { KEY_TYPES } from "@/lib/types";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Input, PasswordInput, Textarea } from "@/components/ui/input";
import { Field, FieldLabel } from "@/components/ui/field";
import { Select } from "@/components/ui/select";
import { Switch, Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/misc";
import { Dialog, DialogContent, DialogFooter, DialogHeader } from "@/components/ui/dialog";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { CertStatusBadge, CodeBlock, EmptyState, ErrorAlert, Expiry, LoadingRows, PageHeader, Pager } from "@/components/common";
import { lines } from "@/components/PolicyForm";
import { useAuthorities } from "@/pages/Authorities";
import { downloadBase64, downloadText, fmtDate } from "@/lib/utils";
import { useTitle } from "@/App";

const LIMIT = 25;

interface IssueResult { certificate: Certificate; keyPem?: string; pfx?: string }

export function IssueDialog({ open, onOpenChange, defaultIssuer }: { open: boolean; onOpenChange: (o: boolean) => void; defaultIssuer?: string }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const auths = useAuthorities();
  const issuers = (auths.data ?? []).filter((a) => a.kind === "intermediate" && a.status === "active");
  const [mode, setMode] = useState<"generate" | "csr">("generate");
  const [f, setF] = useState({ issuer: defaultIssuer ?? "", names: "", csr: "", keyAlgorithm: "ecdsa-p256", validityDays: 0, clientAuth: false, pfxPassword: "" });
  const [res, setRes] = useState<IssueResult | null>(null);
  const issuer = f.issuer || issuers.find((i) => i.isDefault)?.slug || issuers[0]?.slug || "";
  const m = useMutation({
    mutationFn: () =>
      api.post<IssueResult>("/certificates", {
        issuer,
        validityDays: f.validityDays || 0,
        clientAuth: f.clientAuth,
        ...(mode === "csr" ? { csr: f.csr } : { names: lines(f.names), keyAlgorithm: f.keyAlgorithm, pfxPassword: f.pfxPassword }),
      }),
    onSuccess: async (d) => {
      setRes(d);
      toast.success(t("certs.issued"));
      await qc.invalidateQueries({ queryKey: ["certificates"] });
      await qc.invalidateQueries({ queryKey: ["dashboard"] });
    },
  });
  const close = (o: boolean) => {
    onOpenChange(o);
    if (!o) { setRes(null); m.reset(); setF((p) => ({ ...p, names: "", csr: "", pfxPassword: "" })); }
  };
  const base = res ? (res.certificate.commonName || res.certificate.sans?.[0] || "certificate").replace(/^\*\./, "wildcard.") : "";
  return (
    <Dialog open={open} onOpenChange={close}>
      <DialogContent wide>
        {res ? (
          <>
            <DialogHeader title={t("certs.issuedTitle")} description={res.keyPem ? t("certs.issuedKeyWarning") : t("certs.issuedText")} />
            <div className="grid gap-4">
              <div className="flex flex-wrap gap-2">
                <Button variant="outline" size="sm" onClick={() => downloadText(`${base}.crt`, res.certificate.certPem)}><Download aria-hidden /> {t("certs.downloadCert")}</Button>
                <Button variant="outline" size="sm" onClick={() => downloadText(`${base}.fullchain.pem`, res.certificate.certPem + res.certificate.chainPem)}><Download aria-hidden /> {t("certs.downloadFullchain")}</Button>
                {res.keyPem && <Button size="sm" onClick={() => downloadText(`${base}.key`, res.keyPem!)}><Download aria-hidden /> {t("certs.downloadKey")}</Button>}
                {res.pfx && <Button size="sm" onClick={() => downloadBase64(`${base}.pfx`, res.pfx!, "application/x-pkcs12")}><Download aria-hidden /> PFX</Button>}
              </div>
              {res.keyPem && <CodeBlock code={res.keyPem} filename={`${base}.key`} label={t("certs.privateKey")} />}
            </div>
            <DialogFooter>
              <Button variant="outline" asChild><Link to={`/certificates/${res.certificate.id}`} onClick={() => close(false)}>{t("certs.openDetail")}</Link></Button>
              <Button onClick={() => close(false)}>{t("common.done")}</Button>
            </DialogFooter>
          </>
        ) : (
          <>
            <DialogHeader title={t("certs.issue")} description={t("certs.issueText")} />
            <form className="grid gap-4" onSubmit={(e) => { e.preventDefault(); m.mutate(); }}>
              <Field label={t("certs.issuer")} required>
                <Select value={issuer} onValueChange={(v) => setF({ ...f, issuer: v })} options={issuers.map((i) => ({ value: i.slug, label: `${i.name} (${i.slug})` }))} />
              </Field>
              <Tabs value={mode} onValueChange={(v) => setMode(v as "generate" | "csr")}>
                <TabsList>
                  <TabsTrigger value="generate">{t("certs.modeGenerate")}</TabsTrigger>
                  <TabsTrigger value="csr">{t("certs.modeCsr")}</TabsTrigger>
                </TabsList>
                <TabsContent value="generate" className="grid gap-4 sm:grid-cols-2">
                  <Field label={t("certs.names")} hint={t("certs.namesHint")} required className="sm:col-span-2">
                    <Textarea rows={3} className="font-mono text-[13px]" value={f.names} onChange={(e) => setF({ ...f, names: e.target.value })} placeholder={"nas.home.lab\n192.168.1.10"} />
                  </Field>
                  <Field label={t("certs.keyAlgorithm")}>
                    <Select value={f.keyAlgorithm} onValueChange={(v) => setF({ ...f, keyAlgorithm: v })} options={KEY_TYPES.map((k) => ({ value: k, label: k }))} />
                  </Field>
                  <Field label={t("certs.pfxPassword")} hint={t("certs.pfxPasswordHint")}>
                    <PasswordInput value={f.pfxPassword} onChange={(e) => setF({ ...f, pfxPassword: e.target.value })} autoComplete="new-password" />
                  </Field>
                </TabsContent>
                <TabsContent value="csr">
                  <Field label={t("certs.csr")} hint={t("certs.csrHint")} required>
                    <Textarea rows={7} className="font-mono text-xs" value={f.csr} onChange={(e) => setF({ ...f, csr: e.target.value })} placeholder="-----BEGIN CERTIFICATE REQUEST-----" spellCheck={false} />
                  </Field>
                </TabsContent>
              </Tabs>
              <div className="grid gap-4 sm:grid-cols-2">
                <Field label={t("certs.validityDays")} hint={t("certs.validityHint")}>
                  <Input type="number" min={0} max={3650} value={f.validityDays || ""} placeholder="90" onChange={(e) => setF({ ...f, validityDays: Number(e.target.value) })} />
                </Field>
                <div className="flex items-center justify-between gap-4 rounded-lg border px-4 py-3 sm:self-end">
                  <FieldLabel htmlFor="issue-client">{t("policy.clientAuth")}</FieldLabel>
                  <Switch id="issue-client" checked={f.clientAuth} onCheckedChange={(v) => setF({ ...f, clientAuth: v })} />
                </div>
              </div>
              <ErrorAlert error={m.error} />
              <DialogFooter>
                <Button variant="outline" onClick={() => close(false)}>{t("common.cancel")}</Button>
                <Button type="submit" loading={m.isPending} disabled={!issuer || (mode === "csr" ? !f.csr.trim() : !f.names.trim())}>{t("certs.issueAction")}</Button>
              </DialogFooter>
            </form>
          </>
        )}
      </DialogContent>
    </Dialog>
  );
}

export default function Certificates() {
  const { t } = useTranslation();
  useTitle(t("nav.certificates"));
  const [params, setParams] = useSearchParams();
  const status = params.get("status") ?? "";
  const issuer = params.get("issuer") ?? "";
  const qParam = params.get("q") ?? "";
  const offset = Number(params.get("offset") ?? 0);
  const [search, setSearch] = useState(qParam);
  const auths = useAuthorities();
  const set = (patch: Record<string, string>) => {
    const next = new URLSearchParams(params);
    for (const [k, v] of Object.entries(patch)) v ? next.set(k, v) : next.delete(k);
    if (!("offset" in patch)) next.delete("offset");
    setParams(next, { replace: true });
  };
  const filter = { status, issuer, q: qParam, limit: LIMIT, offset };
  const q = useQuery({
    queryKey: ["certificates", filter],
    queryFn: () => api.get<{ items: Certificate[]; total: number }>(`/certificates${qs({ ...filter, withinDays: status === "expiring" ? 30 : undefined })}`),
    placeholderData: (p) => p,
  });
  const issuers = (auths.data ?? []).filter((a) => a.kind === "intermediate");
  return (
    <>
      <PageHeader
        eyebrow={t("nav.groups.pki")}
        title={t("nav.certificates")}
        description={t("certs.description")}
        actions={<Button onClick={() => set({ issue: "1" })}><Plus aria-hidden /> {t("certs.issue")}</Button>}
      />
      <div className="mb-4 flex flex-wrap items-end gap-3">
        <form className="relative min-w-60 flex-1" role="search" onSubmit={(e) => { e.preventDefault(); set({ q: search.trim() }); }}>
          <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" aria-hidden />
          <Input type="search" value={search} onChange={(e) => setSearch(e.target.value)} onBlur={() => search.trim() !== qParam && set({ q: search.trim() })} placeholder={t("certs.searchPlaceholder")} aria-label={t("certs.search")} className="pl-9" />
        </form>
        <Select
          aria-label={t("certs.status")}
          value={status || "all"}
          onValueChange={(v) => set({ status: v === "all" ? "" : v })}
          options={["all", "valid", "expiring", "expired", "revoked"].map((s) => ({ value: s, label: t(`certs.filter.${s}`) }))}
        />
        <Select
          aria-label={t("certs.issuer")}
          value={issuer || "all"}
          onValueChange={(v) => set({ issuer: v === "all" ? "" : v })}
          options={[{ value: "all", label: t("certs.allIssuers") }, ...issuers.map((i) => ({ value: i.slug, label: i.slug }))]}
        />
      </div>
      <ErrorAlert error={q.error} onRetry={() => void q.refetch()} className="mb-4" />
      <Card className="overflow-hidden">
        {q.isPending ? <div className="p-6"><LoadingRows /></div> : !q.data?.items.length ? (
          <EmptyState
            title={status || issuer || qParam ? t("certs.noMatch") : t("certs.empty")}
            description={status || issuer || qParam ? undefined : t("certs.emptyText")}
            action={status || issuer || qParam
              ? <Button variant="outline" onClick={() => { setSearch(""); setParams({}, { replace: true }); }}>{t("certs.clearFilters")}</Button>
              : <Button onClick={() => set({ issue: "1" })}><Plus aria-hidden /> {t("certs.issue")}</Button>}
            className="py-12"
          />
        ) : (
          <>
            <Table>
              <THead>
                <TR>
                  <TH>{t("certs.name")}</TH>
                  <TH className="hidden md:table-cell">{t("certs.issuer")}</TH>
                  <TH className="hidden lg:table-cell">{t("certs.source")}</TH>
                  <TH>{t("certs.status")}</TH>
                  <TH>{t("certs.expires")}</TH>
                </TR>
              </THead>
              <TBody className={q.isPlaceholderData ? "opacity-60" : undefined}>
                {q.data.items.map((c) => {
                  const extra = (c.sans?.length ?? 0) - 1;
                  return (
                    <TR key={c.id}>
                      <TD className="max-w-[22rem]">
                        <Link to={`/certificates/${c.id}`} className="flex items-center gap-2 font-medium hover:underline">
                          <FileBadge className="size-4 shrink-0 text-muted-foreground" aria-hidden />
                          <span className="truncate">{c.commonName || c.sans?.[0] || c.serial}</span>
                        </Link>
                        {extra > 0 && <span className="ml-6 text-xs text-muted-foreground">{t("certs.moreNames", { count: extra })}</span>}
                      </TD>
                      <TD className="hidden md:table-cell"><code className="font-mono text-xs">{c.issuerSlug}</code></TD>
                      <TD className="hidden text-muted-foreground lg:table-cell">{t(`certs.sources.${c.source}`, { defaultValue: c.source })}</TD>
                      <TD><CertStatusBadge status={c.status} notAfter={c.notAfter} /></TD>
                      <TD><span className="grid"><span className="tabular">{fmtDate(c.notAfter)}</span><Expiry value={c.notAfter} warnDays={14} /></span></TD>
                    </TR>
                  );
                })}
              </TBody>
            </Table>
            <Pager total={q.data.total} limit={LIMIT} offset={offset} onChange={(o) => set({ offset: o ? String(o) : "" })} />
          </>
        )}
      </Card>
      <IssueDialog open={params.get("issue") === "1"} onOpenChange={(o) => set({ issue: o ? "1" : "" })} defaultIssuer={issuer || undefined} />
    </>
  );
}
