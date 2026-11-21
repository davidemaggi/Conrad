import { useSearchParams } from "react-router";
import { useTranslation } from "react-i18next";
import { useQuery } from "@tanstack/react-query";
import { api, qs } from "@/lib/api";
import type { AuditEntry } from "@/lib/types";
import { Card } from "@/components/ui/card";
import { Select } from "@/components/ui/select";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { EmptyState, ErrorAlert, LoadingRows, PageHeader, Pager } from "@/components/common";
import { useActionLabel } from "@/components/AuditList";
import { fmtDate } from "@/lib/utils";
import { useTitle } from "@/App";

const LIMIT = 50;
const GROUPS = ["auth", "cert", "order", "challenge", "account", "issuer", "root", "authority", "eab", "policy", "ca", "notify", "settings", "setup", "system"];

function details(d: AuditEntry["details"]) {
  if (!d) return "";
  return Object.entries(d)
    .map(([k, v]) => `${k}=${Array.isArray(v) ? v.join(",") : typeof v === "object" ? JSON.stringify(v) : String(v)}`)
    .join("  ");
}

export default function Audit() {
  const { t } = useTranslation();
  useTitle(t("nav.audit"));
  const label = useActionLabel();
  const [params, setParams] = useSearchParams();
  const action = params.get("action") ?? "";
  const offset = Number(params.get("offset") ?? 0);
  const q = useQuery({
    queryKey: ["audit", action, offset],
    queryFn: () => api.get<{ items: AuditEntry[]; total: number }>(`/audit${qs({ action: action ? action + "." : "", limit: LIMIT, offset })}`),
    placeholderData: (p) => p,
  });
  return (
    <>
      <PageHeader
        eyebrow={t("nav.groups.system")}
        title={t("nav.audit")}
        description={t("audit.description")}
        actions={
          <Select
            aria-label={t("audit.filter")}
            value={action || "all"}
            onValueChange={(v) => setParams(v === "all" ? {} : { action: v }, { replace: true })}
            options={[{ value: "all", label: t("audit.all") }, ...GROUPS.map((g) => ({ value: g, label: t(`audit.groups.${g}`) }))]}
          />
        }
      />
      <ErrorAlert error={q.error} onRetry={() => void q.refetch()} className="mb-4" />
      <Card className="overflow-hidden">
        {q.isPending ? <div className="p-6"><LoadingRows /></div> : !q.data?.items.length ? (
          <EmptyState title={t("audit.empty")} className="py-12" />
        ) : (
          <>
            <Table>
              <THead>
                <TR>
                  <TH className="w-44">{t("audit.when")}</TH>
                  <TH>{t("audit.action")}</TH>
                  <TH>{t("audit.actor")}</TH>
                  <TH className="hidden lg:table-cell">{t("audit.details")}</TH>
                </TR>
              </THead>
              <TBody className={q.isPlaceholderData ? "opacity-60" : undefined}>
                {q.data.items.map((e) => (
                  <TR key={e.id}>
                    <TD className="whitespace-nowrap tabular text-muted-foreground"><time dateTime={e.at}>{fmtDate(e.at, true)}</time></TD>
                    <TD>
                      <span className="font-medium">{label(e.action)}</span>
                      {e.target && <span className="block max-w-72 truncate font-mono text-xs text-muted-foreground" title={e.target}>{e.target}</span>}
                    </TD>
                    <TD>
                      <span className="font-mono text-xs">{e.actor}</span>
                      {e.ip && <span className="block font-mono text-xs text-muted-foreground">{e.ip}</span>}
                    </TD>
                    <TD className="hidden max-w-md lg:table-cell">
                      <span className="line-clamp-2 font-mono text-xs text-muted-foreground wrap-anywhere" title={details(e.details)}>{details(e.details)}</span>
                    </TD>
                  </TR>
                ))}
              </TBody>
            </Table>
            <Pager total={q.data.total} limit={LIMIT} offset={offset} onChange={(o) => setParams({ ...(action ? { action } : {}), ...(o ? { offset: String(o) } : {}) }, { replace: true })} />
          </>
        )}
      </Card>
    </>
  );
}
