import { useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router";
import { useTranslation } from "react-i18next";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { ArrowLeft, Ban, Download, KeyRound, Pencil, Plus, RotateCw, Star } from "lucide-react";
import { api } from "@/lib/api";
import type { Authority, Certificate, EABKey, Policy } from "@/lib/types";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Field } from "@/components/ui/field";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/misc";
import { Dialog, DialogContent, DialogFooter, DialogHeader } from "@/components/ui/dialog";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import {
  AuthorityStatusBadge, CertStatusBadge, CodeBlock, ConfirmDialog, ConfirmTypeDialog, CopyButton, EmptyState, ErrorAlert, Expiry, KV,
  LoadingRows, MonoValue, PageHeader,
} from "@/components/common";
import { PolicyForm } from "@/components/PolicyForm";
import { useAuthorities } from "@/pages/Authorities";
import { colonHex, fmtDate, isZeroTime } from "@/lib/utils";
import { useTitle } from "@/App";

function EditDialog({ a, open, onOpenChange }: { a: Authority; open: boolean; onOpenChange: (o: boolean) => void }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const [name, setName] = useState(a.name);
  const [description, setDescription] = useState(a.description);
  const m = useMutation({
    mutationFn: () => api.patch<Authority>(`/authorities/${a.id}`, { name, description }),
    onSuccess: async () => {
      toast.success(t("common.saved"));
      await qc.invalidateQueries({ queryKey: ["authorities"] });
      onOpenChange(false);
    },
  });
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader title={t("authorities.edit")} />
        <form className="grid gap-4" onSubmit={(e) => { e.preventDefault(); m.mutate(); }}>
          <Field label={t("ca.name")} required><Input value={name} onChange={(e) => setName(e.target.value)} /></Field>
          <Field label={t("ca.description")}><Input value={description} onChange={(e) => setDescription(e.target.value)} /></Field>
          <ErrorAlert error={m.error} />
          <DialogFooter>
            <Button variant="outline" onClick={() => onOpenChange(false)}>{t("common.cancel")}</Button>
            <Button type="submit" loading={m.isPending} disabled={!name.trim()}>{t("common.save")}</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function Overview({ a }: { a: Authority }) {
  const { t } = useTranslation();
  const base = a.kind === "root" ? `/roots/${a.id}` : `/issuers/${a.id}`;
  return (
    <div className="grid gap-6 lg:grid-cols-[1fr_20rem]">
      <Card>
        <CardHeader><CardTitle>{t("authorities.details")}</CardTitle></CardHeader>
        <CardContent>
          <KV
            items={[
              [t("common.subject"), <code className="break-all font-mono text-[13px]">{a.subject}</code>],
              [t("ca.algorithm"), <code className="font-mono text-[13px]">{a.algorithm}</code>],
              [t("certs.serial"), <MonoValue value={a.serial} />],
              [t("certs.fingerprint"), <span className="flex items-start gap-1"><MonoValue value={colonHex(a.fingerprintSha256)} className="text-xs" /><CopyButton value={a.fingerprintSha256} /></span>],
              [t("certs.notBefore"), fmtDate(a.notBefore, true)],
              [t("certs.notAfter"), <span className="flex flex-wrap gap-2">{fmtDate(a.notAfter, true)} <Expiry value={a.notAfter} warnDays={90} /></span>],
              ...(a.nameConstraints?.length ? [[t("ca.nameConstraints"), <span className="font-mono text-[13px]">{a.nameConstraints.join(", ")}</span>] as [string, React.ReactNode]] : []),
              ...(!isZeroTime(a.revokedAt) && a.revokedAt ? [[t("status.revoked"), fmtDate(a.revokedAt, true)] as [string, string]] : []),
              ...(a.crlUrl ? [[t("authorities.crl"), <span className="grid gap-0.5"><a className="break-all font-mono text-[13px] text-primary hover:underline" href={a.crlUrl}>{a.crlUrl}</a>{a.crlUpdatedAt && !isZeroTime(a.crlUpdatedAt) && <span className="text-xs text-muted-foreground">{t("authorities.crlUpdated", { date: fmtDate(a.crlUpdatedAt, true) })}</span>}</span>] as [string, React.ReactNode]] : []),
            ]}
          />
        </CardContent>
      </Card>
      <div className="grid content-start gap-6">
        {a.kind === "intermediate" && a.status === "active" && (
          <Card>
            <CardHeader>
              <CardTitle>{t("authorities.directory")}</CardTitle>
              <CardDescription>{t("authorities.directoryText")}</CardDescription>
            </CardHeader>
            <CardContent className="grid gap-3">
              <div className="flex items-center gap-1 rounded-md border bg-muted/40 py-1 pl-3 pr-1">
                <code className="min-w-0 flex-1 break-all font-mono text-[13px]">{a.directoryUrl}</code>
                <CopyButton value={a.directoryUrl} />
              </div>
              <Button asChild variant="outline" size="sm"><Link to={`/clients?issuer=${a.slug}`}>{t("authorities.clientSnippets")}</Link></Button>
            </CardContent>
          </Card>
        )}
        <Card>
          <CardHeader><CardTitle>{t("common.download")}</CardTitle></CardHeader>
          <CardContent className="flex flex-wrap gap-2">
            {["crt", "pem", ...(a.kind === "root" ? ["mobileconfig"] : [])].map((ext) => (
              <Button key={ext} asChild variant="outline" size="sm">
                <a href={`${base}.${ext}`} download><Download aria-hidden /> .{ext}</a>
              </Button>
            ))}
          </CardContent>
        </Card>
      </div>
      <CodeBlock code={a.certPem} filename={a.kind === "root" ? "conrad-root-ca.pem" : `conrad-${a.slug}.pem`} label={t("certs.pem")} className="lg:col-span-2" />
    </div>
  );
}

function PolicyTab({ a }: { a: Authority }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["policy", a.id], queryFn: () => api.get<Policy>(`/authorities/${a.id}/policy`) });
  const [p, setP] = useState<Policy | null>(null);
  useEffect(() => { if (q.data) setP(q.data); }, [q.data]);
  const m = useMutation({
    mutationFn: (v: Policy) => api.put<Policy>(`/authorities/${a.id}/policy`, v),
    onSuccess: (d) => { toast.success(t("common.saved")); qc.setQueryData(["policy", a.id], d); },
  });
  if (q.error) return <ErrorAlert error={q.error} onRetry={() => void q.refetch()} />;
  if (!p) return <LoadingRows rows={4} />;
  const dirty = JSON.stringify(p) !== JSON.stringify(q.data);
  return (
    <Card>
      <CardHeader>
        <CardTitle>{t("policy.title")}</CardTitle>
        <CardDescription>{t("policy.description")}</CardDescription>
      </CardHeader>
      <CardContent>
        <form className="grid gap-6" onSubmit={(e) => { e.preventDefault(); m.mutate(p); }}>
          <PolicyForm value={p} onChange={setP} />
          <ErrorAlert error={m.error} />
          <div className="flex justify-end gap-2 border-t pt-4">
            <Button variant="outline" disabled={!dirty} onClick={() => q.data && setP(q.data)}>{t("common.reset")}</Button>
            <Button type="submit" loading={m.isPending} disabled={!dirty}>{t("common.save")}</Button>
          </div>
        </form>
      </CardContent>
    </Card>
  );
}

interface CreatedEAB { key: EABKey; kid: string; hmac: string; directoryUrl: string }

function EABTab({ a }: { a: Authority }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const key = ["eab", a.id];
  const q = useQuery({ queryKey: key, queryFn: () => api.get<{ items: EABKey[] }>(`/authorities/${a.id}/eab-keys`), select: (d) => d.items });
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [created, setCreated] = useState<CreatedEAB | null>(null);
  const [revoking, setRevoking] = useState<EABKey | null>(null);
  const create = useMutation({
    mutationFn: () => api.post<CreatedEAB>(`/authorities/${a.id}/eab-keys`, { name }),
    onSuccess: async (d) => { setCreated(d); setName(""); await qc.invalidateQueries({ queryKey: key }); },
  });
  const revoke = useMutation({
    mutationFn: (k: EABKey) => api.del(`/authorities/${a.id}/eab-keys/${k.id}`),
    onSuccess: async () => { setRevoking(null); toast.success(t("eab.revoked")); await qc.invalidateQueries({ queryKey: key }); },
  });
  const close = (o: boolean) => { setOpen(o); if (!o) { setCreated(null); create.reset(); } };
  const certbot = created
    ? `sudo certbot certonly --standalone \\\n  --server ${created.directoryUrl} \\\n  --eab-kid ${created.kid} \\\n  --eab-hmac-key ${created.hmac} \\\n  -d myhost.home.lab`
    : "";
  return (
    <Card>
      <CardHeader className="flex-row flex-wrap items-start justify-between gap-4">
        <div>
          <CardTitle>{t("eab.title")}</CardTitle>
          <CardDescription>{t("eab.description")}</CardDescription>
        </div>
        <Button size="sm" onClick={() => setOpen(true)} disabled={a.status !== "active"}><Plus aria-hidden /> {t("eab.create")}</Button>
      </CardHeader>
      <CardContent className="p-0">
        <ErrorAlert error={q.error} className="mx-6 mb-4" />
        {q.isPending ? <div className="px-6 pb-6"><LoadingRows rows={2} /></div> : !q.data?.length ? (
          <EmptyState title={t("eab.empty")} description={t("eab.emptyText")} className="pb-8" />
        ) : (
          <Table>
            <THead><TR><TH>{t("ca.name")}</TH><TH>{t("eab.kid")}</TH><TH>{t("eab.state")}</TH><TH>{t("common.created")}</TH><TH><span className="sr-only">{t("common.actions")}</span></TH></TR></THead>
            <TBody>
              {q.data.map((k) => {
                const revoked = !!k.revokedAt && !isZeroTime(k.revokedAt);
                return (
                  <TR key={k.id}>
                    <TD className="font-medium">{k.name}</TD>
                    <TD><code className="font-mono text-xs">{k.id}</code></TD>
                    <TD>{revoked ? <Badge variant="danger">{t("status.revoked")}</Badge> : k.boundAccountId ? <Badge variant="success">{t("eab.bound")}</Badge> : <Badge variant="outline">{t("eab.unused")}</Badge>}</TD>
                    <TD className="text-muted-foreground">{fmtDate(k.createdAt)}</TD>
                    <TD className="text-right">
                      {!revoked && <Button variant="ghost" size="sm" className="text-destructive" onClick={() => setRevoking(k)}>{t("eab.revoke")}</Button>}
                    </TD>
                  </TR>
                );
              })}
            </TBody>
          </Table>
        )}
      </CardContent>
      <Dialog open={open} onOpenChange={close}>
        <DialogContent wide={!!created}>
          {created ? (
            <>
              <DialogHeader title={t("eab.createdTitle")} description={t("eab.createdText")} />
              <div className="grid gap-3">
                <KV items={[
                  [t("eab.kid"), <span className="flex items-center gap-1"><MonoValue value={created.kid} /><CopyButton value={created.kid} /></span>],
                  [t("eab.hmac"), <span className="flex items-center gap-1"><MonoValue value={created.hmac} className="break-all" /><CopyButton value={created.hmac} /></span>],
                ]} />
                <CodeBlock code={certbot} label="certbot" />
              </div>
              <DialogFooter><Button onClick={() => close(false)}>{t("common.done")}</Button></DialogFooter>
            </>
          ) : (
            <>
              <DialogHeader title={t("eab.create")} description={t("eab.createText")} />
              <form className="grid gap-4" onSubmit={(e) => { e.preventDefault(); create.mutate(); }}>
                <Field label={t("ca.name")} hint={t("eab.nameHint")} required>
                  <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="nas-01" autoFocus />
                </Field>
                <ErrorAlert error={create.error} />
                <DialogFooter>
                  <Button variant="outline" onClick={() => close(false)}>{t("common.cancel")}</Button>
                  <Button type="submit" loading={create.isPending} disabled={!name.trim()}><KeyRound aria-hidden /> {t("eab.generate")}</Button>
                </DialogFooter>
              </form>
            </>
          )}
        </DialogContent>
      </Dialog>
      <ConfirmDialog
        open={!!revoking}
        onOpenChange={(o) => !o && setRevoking(null)}
        title={t("eab.revoke")}
        description={t("eab.revokeText", { name: revoking?.name })}
        actionLabel={t("eab.revoke")}
        destructive
        onConfirm={() => revoking && revoke.mutate(revoking)}
        loading={revoke.isPending}
        error={revoke.error}
      />
    </Card>
  );
}

function CertsTab({ a }: { a: Authority }) {
  const { t } = useTranslation();
  const q = useQuery({
    queryKey: ["certificates", { issuer: a.slug, limit: 10 }],
    queryFn: () => api.get<{ items: Certificate[]; total: number }>(`/certificates?issuer=${encodeURIComponent(a.slug)}&limit=10`),
  });
  return (
    <Card>
      <CardHeader className="flex-row items-center justify-between gap-4">
        <CardTitle>{t("nav.certificates")}</CardTitle>
        <Button asChild variant="outline" size="sm"><Link to={`/certificates?issuer=${a.slug}`}>{t("common.viewAll")}</Link></Button>
      </CardHeader>
      <CardContent className="p-0">
        <ErrorAlert error={q.error} className="mx-6 mb-4" />
        {q.isPending ? <div className="px-6 pb-6"><LoadingRows rows={3} /></div> : !q.data?.items.length ? (
          <EmptyState title={t("certs.empty")} className="pb-8" />
        ) : (
          <Table>
            <THead><TR><TH>{t("certs.name")}</TH><TH>{t("certs.status")}</TH><TH>{t("certs.expires")}</TH></TR></THead>
            <TBody>
              {q.data.items.map((c) => (
                <TR key={c.id}>
                  <TD><Link to={`/certificates/${c.id}`} className="font-medium hover:underline">{c.commonName || c.sans?.[0] || c.serial}</Link></TD>
                  <TD><CertStatusBadge status={c.status} notAfter={c.notAfter} /></TD>
                  <TD><Expiry value={c.notAfter} warnDays={14} /></TD>
                </TR>
              ))}
            </TBody>
          </Table>
        )}
      </CardContent>
    </Card>
  );
}

function IssuersOfRoot({ a, all }: { a: Authority; all: Authority[] }) {
  const { t } = useTranslation();
  const kids = all.filter((x) => x.parentId === a.id);
  return (
    <Card>
      <CardHeader><CardTitle>{t("authorities.issuers")}</CardTitle></CardHeader>
      <CardContent className="p-0">
        {!kids.length ? <EmptyState title={t("authorities.noIssuers")} className="pb-8" /> : (
          <Table>
            <THead><TR><TH>{t("ca.name")}</TH><TH>{t("ca.slug")}</TH><TH>{t("certs.status")}</TH><TH>{t("certs.expires")}</TH></TR></THead>
            <TBody>
              {kids.map((k) => (
                <TR key={k.id}>
                  <TD><Link to={`/authorities/${k.id}`} className="font-medium hover:underline">{k.name}</Link></TD>
                  <TD><code className="font-mono text-xs">{k.slug}</code></TD>
                  <TD><AuthorityStatusBadge status={k.status} /></TD>
                  <TD><Expiry value={k.notAfter} warnDays={90} /></TD>
                </TR>
              ))}
            </TBody>
          </Table>
        )}
      </CardContent>
    </Card>
  );
}

export default function AuthorityDetail() {
  const { id = "" } = useParams();
  const { t } = useTranslation();
  const nav = useNavigate();
  const qc = useQueryClient();
  const list = useAuthorities();
  const a = list.data?.find((x) => x.id === id);
  useTitle(a?.name ?? t("nav.authorities"));
  const [dlg, setDlg] = useState<"" | "edit" | "rotate" | "revoke" | "default">("");
  const done = async (msg: string) => {
    setDlg("");
    toast.success(msg);
    await qc.invalidateQueries({ queryKey: ["authorities"] });
  };
  const rotate = useMutation({
    mutationFn: () => api.post<Authority>(`/authorities/${id}/rotate`, {}),
    onSuccess: async (n) => { await done(t("authorities.rotated")); nav(`/authorities/${n.id}`); },
  });
  const revoke = useMutation({ mutationFn: () => api.post(`/authorities/${id}/revoke`, { confirm: a?.slug }), onSuccess: () => done(t("authorities.revokedToast")) });
  const setDefault = useMutation({ mutationFn: () => api.post(`/authorities/${id}/default`, {}), onSuccess: () => done(t("authorities.defaultChanged")) });

  if (list.error) return <ErrorAlert error={list.error} onRetry={() => void list.refetch()} />;
  if (list.isPending) return <LoadingRows rows={6} />;
  if (!a) return <EmptyState title={t("errors.not_found")} action={<Button asChild variant="outline"><Link to="/authorities">{t("common.back")}</Link></Button>} />;

  const issuer = a.kind === "intermediate";
  const active = a.status === "active";
  return (
    <>
      <Link to="/authorities" className="mb-3 inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground">
        <ArrowLeft className="size-4" aria-hidden /> {t("nav.authorities")}
      </Link>
      <PageHeader
        eyebrow={issuer ? <code className="font-mono normal-case">{a.slug}</code> : t("authorities.root")}
        title={
          <span className="flex flex-wrap items-center gap-3">
            {a.name}
            <AuthorityStatusBadge status={a.status} />
            {a.isDefault && <Badge variant="info">{t("authorities.default")}</Badge>}
          </span>
        }
        description={a.description || undefined}
        actions={
          <>
            <Button variant="outline" onClick={() => setDlg("edit")}><Pencil aria-hidden /> {t("common.edit")}</Button>
            {issuer && active && !a.isDefault && <Button variant="outline" onClick={() => setDlg("default")}><Star aria-hidden /> {t("authorities.setDefault")}</Button>}
            {issuer && active && <Button variant="outline" onClick={() => setDlg("rotate")}><RotateCw aria-hidden /> {t("authorities.rotate")}</Button>}
            {issuer && active && !a.isDefault && <Button variant="destructive" onClick={() => setDlg("revoke")}><Ban aria-hidden /> {t("authorities.revoke")}</Button>}
          </>
        }
      />
      <Tabs defaultValue="overview">
        <TabsList>
          <TabsTrigger value="overview">{t("authorities.tabs.overview")}</TabsTrigger>
          {issuer ? (
            <>
              <TabsTrigger value="policy">{t("authorities.tabs.policy")}</TabsTrigger>
              <TabsTrigger value="eab">{t("authorities.tabs.eab")}</TabsTrigger>
              <TabsTrigger value="certs">{t("authorities.tabs.certs")}</TabsTrigger>
            </>
          ) : (
            <TabsTrigger value="issuers">{t("authorities.issuers")}</TabsTrigger>
          )}
        </TabsList>
        <TabsContent value="overview"><Overview a={a} /></TabsContent>
        {issuer ? (
          <>
            <TabsContent value="policy"><PolicyTab a={a} /></TabsContent>
            <TabsContent value="eab"><EABTab a={a} /></TabsContent>
            <TabsContent value="certs"><CertsTab a={a} /></TabsContent>
          </>
        ) : (
          <TabsContent value="issuers"><IssuersOfRoot a={a} all={list.data ?? []} /></TabsContent>
        )}
      </Tabs>
      <EditDialog key={a.id + dlg} a={a} open={dlg === "edit"} onOpenChange={(o) => setDlg(o ? "edit" : "")} />
      <ConfirmDialog
        open={dlg === "rotate"} onOpenChange={(o) => setDlg(o ? "rotate" : "")}
        title={t("authorities.rotate")} description={t("authorities.rotateText", { slug: a.slug })} actionLabel={t("authorities.rotate")}
        onConfirm={() => rotate.mutate()} loading={rotate.isPending} error={rotate.error}
      />
      <ConfirmDialog
        open={dlg === "default"} onOpenChange={(o) => setDlg(o ? "default" : "")}
        title={t("authorities.setDefault")} description={t("authorities.setDefaultText", { name: a.name })} actionLabel={t("authorities.setDefault")}
        onConfirm={() => setDefault.mutate()} loading={setDefault.isPending} error={setDefault.error}
      />
      <ConfirmTypeDialog
        open={dlg === "revoke"} onOpenChange={(o) => setDlg(o ? "revoke" : "")}
        title={t("authorities.revoke")} description={t("authorities.revokeText")} expected={a.slug} actionLabel={t("authorities.revoke")}
        onConfirm={() => revoke.mutate()} loading={revoke.isPending} error={revoke.error}
      />
    </>
  );
}
