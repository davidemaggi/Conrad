import { Link } from "react-router";
import { useTranslation } from "react-i18next";
import { useQuery } from "@tanstack/react-query";
import { ArrowRight, Building2, FileBadge, Plus, ShieldAlert, Timer, Users } from "lucide-react";
import { api } from "@/lib/api";
import type { Dashboard as D } from "@/lib/types";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/misc";
import { AuthorityStatusBadge, EmptyState, ErrorAlert, Expiry, PageHeader } from "@/components/common";
import { AuditList } from "@/components/AuditList";
import { cn, daysUntil, fmtNumber } from "@/lib/utils";
import { useTitle } from "@/App";

const WINDOW = 14;

function Stat({ label, value, icon: Icon, to, tone }: { label: string; value?: number; icon: typeof FileBadge; to: string; tone?: "warn" | "danger" }) {
  return (
    <Link to={to} className="group rounded-xl border bg-card p-4 transition-colors hover:border-primary/40 sm:p-5">
      <div className="flex items-center justify-between">
        <span className="text-sm text-muted-foreground">{label}</span>
        <Icon className={cn("size-4 text-muted-foreground", tone === "warn" && value ? "text-warning" : "", tone === "danger" && value ? "text-destructive" : "")} aria-hidden />
      </div>
      {value === undefined ? (
        <Skeleton className="mt-3 h-8 w-16" />
      ) : (
        <div className={cn("mt-2 text-3xl font-semibold tabular tracking-tight", tone === "warn" && value ? "text-warning" : "")}>{fmtNumber(value)}</div>
      )}
    </Link>
  );
}

export default function Dashboard() {
  const { t } = useTranslation();
  useTitle(t("nav.dashboard"));
  const q = useQuery({ queryKey: ["dashboard"], queryFn: () => api.get<D>(`/dashboard?withinDays=${WINDOW}`), refetchInterval: 60_000 });
  const d = q.data;
  return (
    <>
      <PageHeader
        eyebrow={t("dashboard.eyebrow")}
        title={t("nav.dashboard")}
        description={t("dashboard.description")}
        actions={
          <Button asChild>
            <Link to="/certificates?issue=1"><Plus aria-hidden /> {t("certs.issue")}</Link>
          </Button>
        }
      />
      <ErrorAlert error={q.error} onRetry={() => void q.refetch()} className="mb-6" />
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4 lg:gap-4">
        <Stat label={t("dashboard.active")} value={d?.stats.active} icon={FileBadge} to="/certificates?status=valid" />
        <Stat label={t("dashboard.expiring", { count: WINDOW })} value={d?.stats.expiring} icon={Timer} to={`/certificates?status=expiring&withinDays=${WINDOW}`} tone="warn" />
        <Stat label={t("dashboard.revoked")} value={d?.stats.revoked} icon={ShieldAlert} to="/certificates?status=revoked" />
        <Stat label={t("dashboard.accounts")} value={d?.accounts} icon={Users} to="/accounts" />
      </div>

      <div className="mt-6 grid gap-6 xl:grid-cols-[1fr_24rem]">
        <div className="grid gap-6">
          <Card>
            <CardHeader className="flex-row items-center justify-between">
              <CardTitle>{t("dashboard.expiringSoon")}</CardTitle>
              <Button asChild variant="link" size="sm">
                <Link to={`/certificates?status=expiring&withinDays=${WINDOW}`}>{t("common.viewAll")} <ArrowRight aria-hidden /></Link>
              </Button>
            </CardHeader>
            <CardContent>
              {!d ? (
                <Skeleton className="h-24" />
              ) : d.expiring.length === 0 ? (
                <EmptyState title={t("dashboard.nothingExpiring")} description={t("dashboard.nothingExpiringText")} className="py-6" />
              ) : (
                <ul className="divide-y">
                  {d.expiring.map((c) => (
                    <li key={c.id}>
                      <Link to={`/certificates/${c.id}`} className="-mx-2 flex items-center gap-3 rounded-md px-2 py-2.5 hover:bg-accent/60">
                        <div className="min-w-0 flex-1">
                          <p className="truncate text-sm font-medium">{c.commonName || c.sans?.[0] || c.serial}</p>
                          <p className="truncate text-xs text-muted-foreground">{c.issuerSlug}{c.sans && c.sans.length > 1 ? ` · +${c.sans.length - 1}` : ""}</p>
                        </div>
                        <Badge variant={daysUntil(c.notAfter) <= 3 ? "danger" : "warning"}>{t("status.expiresIn", { count: daysUntil(c.notAfter) })}</Badge>
                      </Link>
                    </li>
                  ))}
                </ul>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex-row items-center justify-between">
              <CardTitle>{t("nav.authorities")}</CardTitle>
              <Button asChild variant="link" size="sm">
                <Link to="/authorities">{t("common.manage")} <ArrowRight aria-hidden /></Link>
              </Button>
            </CardHeader>
            <CardContent className="px-0 pb-2">
              {!d ? (
                <div className="px-5 pb-3"><Skeleton className="h-24" /></div>
              ) : (
                <ul className="divide-y border-t">
                  {(d.authorities ?? []).map((a) => (
                    <li key={a.id}>
                      <Link to={`/authorities/${a.id}`} className="flex flex-wrap items-center gap-x-4 gap-y-1 px-5 py-3 hover:bg-accent/50">
                        <Building2 className="size-4 shrink-0 text-muted-foreground" aria-hidden />
                        <div className="min-w-0 flex-1">
                          <p className="flex items-center gap-2 text-sm font-medium">
                            {a.name}
                            {a.kind === "root" && <Badge variant="stamp" className="text-ink">{t("authorities.root")}</Badge>}
                            {a.isDefault && <Badge variant="info">{t("authorities.default")}</Badge>}
                          </p>
                          <p className="font-mono text-xs text-muted-foreground">{a.kind === "root" ? a.algorithm : `/acme/${a.slug}/directory`}</p>
                        </div>
                        <span className="text-sm"><Expiry value={a.notAfter} warnDays={90} /></span>
                        <AuthorityStatusBadge status={a.status} />
                      </Link>
                    </li>
                  ))}
                </ul>
              )}
            </CardContent>
          </Card>
        </div>

        <Card className="self-start">
          <CardHeader className="flex-row items-center justify-between">
            <CardTitle>{t("dashboard.recentActivity")}</CardTitle>
            <Button asChild variant="link" size="sm">
              <Link to="/audit">{t("common.viewAll")} <ArrowRight aria-hidden /></Link>
            </Button>
          </CardHeader>
          <CardContent>
            {!d ? <Skeleton className="h-48" /> : d.recentActivity.length ? <AuditList items={d.recentActivity} /> : <p className="text-sm text-muted-foreground">{t("audit.empty")}</p>}
          </CardContent>
        </Card>
      </div>
    </>
  );
}
