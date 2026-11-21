import { useState } from "react";
import { useSearchParams } from "react-router";
import { useTranslation } from "react-i18next";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { api, qs } from "@/lib/api";
import type { Account } from "@/lib/types";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card } from "@/components/ui/card";
import { Select } from "@/components/ui/select";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { ConfirmDialog, EmptyState, ErrorAlert, LoadingRows, PageHeader } from "@/components/common";
import { Tooltip } from "@/components/ui/misc";
import { useAuthorities } from "@/pages/Authorities";
import { fmtDate, fmtNumber, shortFingerprint } from "@/lib/utils";
import { useTitle } from "@/App";

export default function Accounts() {
  const { t } = useTranslation();
  useTitle(t("nav.accounts"));
  const qc = useQueryClient();
  const [params, setParams] = useSearchParams();
  const issuer = params.get("issuer") ?? "";
  const auths = useAuthorities();
  const q = useQuery({ queryKey: ["accounts", issuer], queryFn: () => api.get<{ items: Account[] }>(`/accounts${qs({ issuer })}`), select: (d) => d.items });
  const [target, setTarget] = useState<Account | null>(null);
  const m = useMutation({
    mutationFn: (a: Account) => api.post(`/accounts/${a.id}/deactivate`, {}),
    onSuccess: async () => { setTarget(null); toast.success(t("accounts.deactivated")); await qc.invalidateQueries({ queryKey: ["accounts"] }); },
  });
  return (
    <>
      <PageHeader
        eyebrow={t("nav.groups.pki")}
        title={t("nav.accounts")}
        description={t("accounts.description")}
        actions={
          <Select
            aria-label={t("certs.issuer")}
            value={issuer || "all"}
            onValueChange={(v) => setParams(v === "all" ? {} : { issuer: v }, { replace: true })}
            options={[{ value: "all", label: t("certs.allIssuers") }, ...(auths.data ?? []).filter((a) => a.kind === "intermediate").map((a) => ({ value: a.slug, label: a.slug }))]}
          />
        }
      />
      <ErrorAlert error={q.error} onRetry={() => void q.refetch()} className="mb-4" />
      <Card className="overflow-hidden">
        {q.isPending ? <div className="p-6"><LoadingRows /></div> : !q.data?.length ? (
          <EmptyState title={t("accounts.empty")} description={t("accounts.emptyText")} className="py-12" />
        ) : (
          <Table>
            <THead>
              <TR>
                <TH>{t("accounts.account")}</TH>
                <TH>{t("certs.issuer")}</TH>
                <TH className="hidden md:table-cell">{t("accounts.contacts")}</TH>
                <TH className="text-right">{t("accounts.orders")}</TH>
                <TH className="text-right">{t("nav.certificates")}</TH>
                <TH>{t("certs.status")}</TH>
                <TH className="hidden lg:table-cell">{t("common.created")}</TH>
                <TH><span className="sr-only">{t("common.actions")}</span></TH>
              </TR>
            </THead>
            <TBody>
              {q.data.map((a) => (
                <TR key={a.id}>
                  <TD>
                    <code className="font-mono text-xs">{a.id}</code>
                    <Tooltip content={<span className="font-mono text-xs">{a.jwkThumbprint}</span>}>
                      <p className="w-fit text-xs text-muted-foreground" tabIndex={0}>JWK {shortFingerprint(a.jwkThumbprint)}</p>
                    </Tooltip>
                  </TD>
                  <TD><code className="font-mono text-xs">{a.issuerSlug}</code></TD>
                  <TD className="hidden max-w-60 truncate text-muted-foreground md:table-cell">{a.contacts?.map((c) => c.replace(/^mailto:/, "")).join(", ") || "—"}</TD>
                  <TD className="text-right tabular">{fmtNumber(a.orderCount)}</TD>
                  <TD className="text-right tabular">{fmtNumber(a.certCount)}</TD>
                  <TD>
                    <span className="flex flex-wrap gap-1">
                      <Badge variant={a.status === "valid" ? "success" : "outline"}>{t(`accounts.status.${a.status}`, { defaultValue: a.status })}</Badge>
                      {a.eabKeyId && <Badge variant="info">EAB</Badge>}
                    </span>
                  </TD>
                  <TD className="hidden text-muted-foreground lg:table-cell">{fmtDate(a.createdAt)}</TD>
                  <TD className="text-right">
                    {a.status === "valid" && <Button variant="ghost" size="sm" className="text-destructive" onClick={() => setTarget(a)}>{t("accounts.deactivate")}</Button>}
                  </TD>
                </TR>
              ))}
            </TBody>
          </Table>
        )}
      </Card>
      <ConfirmDialog
        open={!!target}
        onOpenChange={(o) => !o && setTarget(null)}
        title={t("accounts.deactivate")}
        description={t("accounts.deactivateText")}
        actionLabel={t("accounts.deactivate")}
        destructive
        onConfirm={() => target && m.mutate(target)}
        loading={m.isPending}
        error={m.error}
      />
    </>
  );
}
