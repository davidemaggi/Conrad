import { useState } from "react";
import { Link, useParams } from "react-router";
import { useTranslation } from "react-i18next";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { ArrowLeft, Ban, Download } from "lucide-react";
import { api } from "@/lib/api";
import type { Certificate } from "@/lib/types";
import { REVOCATION_REASONS } from "@/lib/types";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Field } from "@/components/ui/field";
import { Select } from "@/components/ui/select";
import { CertStatusBadge, CodeBlock, ConfirmTypeDialog, CopyButton, ErrorAlert, Expiry, KV, LoadingRows, MonoValue, PageHeader } from "@/components/common";
import { colonHex, downloadText, fmtDate, isZeroTime } from "@/lib/utils";
import { useTitle } from "@/App";

export default function CertificateDetail() {
  const { id = "" } = useParams();
  const { t } = useTranslation();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["certificate", id], queryFn: () => api.get<Certificate>(`/certificates/${id}`) });
  const c = q.data;
  const name = c ? c.commonName || c.sans?.[0] || c.serial : "";
  useTitle(name || t("nav.certificates"));
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState("0");
  const revoke = useMutation({
    mutationFn: () => api.post(`/certificates/${id}/revoke`, { reason: Number(reason) }),
    onSuccess: async () => {
      setOpen(false);
      toast.success(t("certs.revokedToast"));
      await qc.invalidateQueries({ queryKey: ["certificate", id] });
      await qc.invalidateQueries({ queryKey: ["certificates"] });
    },
  });
  if (q.error) return <ErrorAlert error={q.error} onRetry={() => void q.refetch()} />;
  if (!c) return <LoadingRows rows={6} />;
  const file = name.replace(/^\*\./, "wildcard.");
  const revoked = c.status === "revoked";
  return (
    <>
      <Link to="/certificates" className="mb-3 inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground">
        <ArrowLeft className="size-4" aria-hidden /> {t("nav.certificates")}
      </Link>
      <PageHeader
        eyebrow={<code className="font-mono normal-case">{c.issuerSlug}</code>}
        title={<span className="flex flex-wrap items-center gap-3 wrap-anywhere">{name}<CertStatusBadge status={c.status} notAfter={c.notAfter} /></span>}
        actions={
          <>
            <Button variant="outline" onClick={() => downloadText(`${file}.crt`, c.certPem)}><Download aria-hidden /> {t("certs.downloadCert")}</Button>
            <Button variant="outline" onClick={() => downloadText(`${file}.fullchain.pem`, c.certPem + c.chainPem)}><Download aria-hidden /> {t("certs.downloadFullchain")}</Button>
            {!revoked && <Button variant="destructive" onClick={() => setOpen(true)}><Ban aria-hidden /> {t("certs.revoke")}</Button>}
          </>
        }
      />
      <div className="grid gap-6 lg:grid-cols-[1fr_20rem]">
        <Card>
          <CardHeader><CardTitle>{t("authorities.details")}</CardTitle></CardHeader>
          <CardContent>
            <KV
              items={[
                [t("certs.serial"), <span className="flex items-center gap-1"><MonoValue value={c.serial} /><CopyButton value={c.serial} /></span>],
                [t("certs.fingerprint"), <span className="flex items-start gap-1"><MonoValue value={colonHex(c.fingerprintSha256)} className="text-xs" /><CopyButton value={c.fingerprintSha256} /></span>],
                [t("certs.keyAlgorithm"), <code className="font-mono text-[13px]">{c.keyAlgorithm}</code>],
                [t("certs.notBefore"), fmtDate(c.notBefore, true)],
                [t("certs.notAfter"), <span className="flex flex-wrap gap-2">{fmtDate(c.notAfter, true)} {!revoked && <Expiry value={c.notAfter} warnDays={14} />}</span>],
                [t("certs.source"), t(`certs.sources.${c.source}`, { defaultValue: c.source })],
                ...(c.accountId ? [[t("certs.account"), <Link to={`/accounts?issuer=${c.issuerSlug}`} className="font-mono text-[13px] text-primary hover:underline">{c.accountId}</Link>] as [string, React.ReactNode]] : []),
                ...(revoked && !isZeroTime(c.revokedAt) ? [[t("status.revoked"), `${fmtDate(c.revokedAt, true)} · ${t(`certs.reasons.${REVOCATION_REASONS[c.revocationReason] ?? "unspecified"}`)}`] as [string, string]] : []),
              ]}
            />
          </CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle>{t("certs.sans")}</CardTitle></CardHeader>
          <CardContent>
            <ul className="flex flex-wrap gap-1.5">
              {(c.sans ?? []).map((s) => (
                <li key={s}><Badge variant="outline" className="font-mono text-xs font-normal normal-case">{s}</Badge></li>
              ))}
            </ul>
          </CardContent>
        </Card>
        <CodeBlock code={c.certPem} filename={`${file}.crt`} label={t("certs.pem")} className="lg:col-span-2" />
        {c.chainPem && <CodeBlock code={c.chainPem} filename="chain.pem" label={t("certs.chain")} className="lg:col-span-2" />}
      </div>
      <ConfirmTypeDialog
        open={open}
        onOpenChange={setOpen}
        title={t("certs.revoke")}
        description={t("certs.revokeText")}
        expected={c.sans?.[0] ?? c.serial}
        actionLabel={t("certs.revoke")}
        onConfirm={() => revoke.mutate()}
        loading={revoke.isPending}
        error={revoke.error}
      >
        <Field label={t("certs.reason")}>
          <Select value={reason} onValueChange={setReason} options={Object.entries(REVOCATION_REASONS).map(([k, v]) => ({ value: k, label: t(`certs.reasons.${v}`) }))} />
        </Field>
      </ConfirmTypeDialog>
    </>
  );
}
