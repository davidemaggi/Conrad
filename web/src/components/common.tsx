import { useState, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";
import { AlertTriangle, Check, ChevronLeft, ChevronRight, Copy, Download, RefreshCw } from "lucide-react";
import { ApiError } from "@/lib/api";
import { cn, daysUntil, fmtDate, isZeroTime } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Dialog, DialogContent, DialogFooter, DialogHeader } from "@/components/ui/dialog";
import { Field } from "@/components/ui/field";
import { Skeleton } from "@/components/ui/misc";
import { Logo } from "@/components/Logo";

/** Translates an API error code (i18n key) with a fallback to the server message. */
export function useErrorText() {
  const { t, i18n } = useTranslation();
  return (err: unknown): string => {
    if (err instanceof ApiError) {
      const key = `errors.${err.code}`;
      if (i18n.exists(key)) return t(key, { ...err.details, message: err.message });
      return err.message || t("errors.internal");
    }
    return err instanceof Error ? err.message : String(err);
  };
}

export function ErrorAlert({ error, onRetry, className }: { error: unknown; onRetry?: () => void; className?: string }) {
  const msg = useErrorText();
  const { t } = useTranslation();
  if (!error) return null;
  return (
    <div role="alert" className={cn("flex items-start gap-3 rounded-lg border border-destructive/30 bg-destructive/8 p-3 text-sm text-destructive", className)}>
      <AlertTriangle className="mt-0.5 size-4 shrink-0" aria-hidden />
      <p className="flex-1 wrap-anywhere">{msg(error)}</p>
      {onRetry && (
        <Button size="sm" variant="ghost" className="-my-1 h-7 text-destructive hover:text-destructive" onClick={onRetry}>
          <RefreshCw aria-hidden /> {t("common.retry")}
        </Button>
      )}
    </div>
  );
}

export function PageHeader({ title, description, actions, eyebrow }: { title: ReactNode; description?: ReactNode; actions?: ReactNode; eyebrow?: ReactNode }) {
  return (
    <div className="mb-6 flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
      <div className="min-w-0">
        {eyebrow && <div className="stamp-label mb-1.5">{eyebrow}</div>}
        <h1 className="text-2xl font-semibold tracking-tight text-balance">{title}</h1>
        {description && <p className="mt-1.5 max-w-2xl text-sm text-muted-foreground text-pretty">{description}</p>}
      </div>
      {actions && <div className="flex shrink-0 flex-wrap gap-2">{actions}</div>}
    </div>
  );
}

export function CopyButton({ value, label, className, size = "icon-sm" }: { value: string; label?: string; className?: string; size?: "icon-sm" | "sm" }) {
  const { t } = useTranslation();
  const [done, setDone] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setDone(true);
      setTimeout(() => setDone(false), 1500);
    } catch {
      toast.error(t("common.copyFailed"));
    }
  };
  const Icon = done ? Check : Copy;
  if (size === "sm")
    return (
      <Button variant="outline" size="sm" onClick={copy} className={className}>
        <Icon aria-hidden /> {done ? t("common.copied") : (label ?? t("common.copy"))}
      </Button>
    );
  return (
    <Button variant="ghost" size="icon-sm" onClick={copy} className={className} aria-label={label ?? t("common.copy")}>
      <Icon aria-hidden className={done ? "text-success" : undefined} />
      <span className="sr-only" aria-live="polite">{done ? t("common.copied") : ""}</span>
    </Button>
  );
}

export function CodeBlock({ code, className, filename, label }: { code: string; className?: string; filename?: string; label?: string }) {
  const { t } = useTranslation();
  return (
    <div className={cn("group relative rounded-lg border bg-muted/60", className)}>
      {label && <div className="border-b px-3 py-1.5 text-xs font-medium text-muted-foreground">{label}</div>}
      <pre className="max-h-96 overflow-auto p-3 pr-20 font-mono text-[12.5px] leading-relaxed whitespace-pre"><code>{code}</code></pre>
      <div className="absolute right-1.5 top-1.5 flex gap-0.5">
        {filename && (
          <Button
            variant="ghost"
            size="icon-sm"
            aria-label={t("common.download")}
            onClick={() => {
              const a = document.createElement("a");
              a.href = URL.createObjectURL(new Blob([code], { type: "text/plain" }));
              a.download = filename;
              a.click();
            }}
          >
            <Download aria-hidden />
          </Button>
        )}
        <CopyButton value={code} />
      </div>
    </div>
  );
}

/** Mono value with a copy button (serials, fingerprints, URLs). */
export function MonoValue({ value, className, truncate }: { value: string; className?: string; truncate?: boolean }) {
  return (
    <span className={cn("inline-flex min-w-0 max-w-full items-center gap-1", className)}>
      <code className={cn("min-w-0 font-mono text-[12.5px]", truncate ? "truncate" : "wrap-anywhere")} title={value}>{value}</code>
      <CopyButton value={value} className="size-7 shrink-0" />
    </span>
  );
}

export function KV({ items, className }: { items: [ReactNode, ReactNode][]; className?: string }) {
  return (
    <dl className={cn("grid gap-x-6 gap-y-3 text-sm sm:grid-cols-[minmax(8rem,auto)_1fr]", className)}>
      {items.map(([k, v], i) => (
        <div key={i} className="contents">
          <dt className="text-muted-foreground">{k}</dt>
          <dd className="min-w-0 wrap-anywhere">{v}</dd>
        </div>
      ))}
    </dl>
  );
}

export function EmptyState({ title, description, action, className }: { title: ReactNode; description?: ReactNode; action?: ReactNode; className?: string }) {
  return (
    <div className={cn("flex flex-col items-center justify-center gap-3 px-6 py-12 text-center", className)}>
      <div className="relative">
        <Logo size={56} simple className="opacity-90" title="" />
      </div>
      <div>
        <p className="font-medium">{title}</p>
        {description && <p className="mx-auto mt-1 max-w-sm text-sm text-muted-foreground text-pretty">{description}</p>}
      </div>
      {action}
    </div>
  );
}

export function LoadingRows({ rows = 5 }: { rows?: number }) {
  return (
    <div className="grid gap-2 p-4" aria-busy="true">
      {Array.from({ length: rows }).map((_, i) => (
        <Skeleton key={i} className="h-10" />
      ))}
    </div>
  );
}

/** Status of a leaf certificate, combining revocation and expiry. */
export function CertStatusBadge({ status, notAfter, warnDays = 14 }: { status: string; notAfter: string; warnDays?: number }) {
  const { t } = useTranslation();
  if (status === "revoked") return <Badge variant="danger">{t("status.revoked")}</Badge>;
  const d = daysUntil(notAfter);
  if (d <= 0) return <Badge variant="outline">{t("status.expired")}</Badge>;
  if (d <= warnDays) return <Badge variant="warning">{t("status.expiresIn", { count: d })}</Badge>;
  return <Badge variant="success">{t("status.valid")}</Badge>;
}

export function AuthorityStatusBadge({ status }: { status: string }) {
  const { t } = useTranslation();
  const v = status === "active" ? "success" : status === "revoked" ? "danger" : "outline";
  return <Badge variant={v}>{t(`status.${status}`, { defaultValue: status })}</Badge>;
}

export function Expiry({ value, warnDays = 30 }: { value: string; warnDays?: number }) {
  const { t } = useTranslation();
  if (isZeroTime(value)) return <span>—</span>;
  const d = daysUntil(value);
  return (
    <span className="tabular whitespace-nowrap">
      {fmtDate(value)}
      <span className={cn("ml-1.5 text-xs", d <= 0 ? "text-destructive" : d <= warnDays ? "text-warning" : "text-muted-foreground")}>
        {d <= 0 ? t("status.expired") : t("common.inDays", { count: d })}
      </span>
    </span>
  );
}

/** Two-step destructive confirmation: the user types `expected` to enable the action. */
export function ConfirmTypeDialog({
  open,
  onOpenChange,
  title,
  description,
  expected,
  actionLabel,
  onConfirm,
  loading,
  error,
  children,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  title: ReactNode;
  description: ReactNode;
  expected: string;
  actionLabel: ReactNode;
  onConfirm: () => void;
  loading?: boolean;
  error?: unknown;
  children?: ReactNode;
}) {
  const { t } = useTranslation();
  const [typed, setTyped] = useState("");
  return (
    <Dialog
      open={open}
      onOpenChange={(o) => {
        if (!o) setTyped("");
        onOpenChange(o);
      }}
    >
      <DialogContent>
        <DialogHeader title={title} description={description} />
        <form
          className="grid gap-4"
          onSubmit={(e) => {
            e.preventDefault();
            if (typed === expected) onConfirm();
          }}
        >
          {children}
          <Field label={<>{t("common.typeToConfirm")} <code className="rounded bg-muted px-1 font-mono">{expected}</code></>}>
            <Input value={typed} onChange={(e) => setTyped(e.target.value)} autoComplete="off" spellCheck={false} />
          </Field>
          <ErrorAlert error={error} />
          <DialogFooter>
            <Button variant="outline" onClick={() => onOpenChange(false)}>{t("common.cancel")}</Button>
            <Button type="submit" variant="destructive" disabled={typed !== expected} loading={loading}>{actionLabel}</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

/** Simple yes/no confirmation. */
export function ConfirmDialog({
  open,
  onOpenChange,
  title,
  description,
  actionLabel,
  onConfirm,
  loading,
  destructive,
  error,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  title: ReactNode;
  description: ReactNode;
  actionLabel: ReactNode;
  onConfirm: () => void;
  loading?: boolean;
  destructive?: boolean;
  error?: unknown;
}) {
  const { t } = useTranslation();
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader title={title} description={description} />
        <ErrorAlert error={error} />
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>{t("common.cancel")}</Button>
          <Button variant={destructive ? "destructive" : "default"} onClick={onConfirm} loading={loading}>{actionLabel}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export function Pager({ total, limit, offset, onChange }: { total: number; limit: number; offset: number; onChange: (o: number) => void }) {
  const { t } = useTranslation();
  if (total <= limit) return null;
  const from = offset + 1;
  const to = Math.min(offset + limit, total);
  return (
    <div className="flex items-center justify-between gap-2 border-t px-4 py-3 text-sm text-muted-foreground">
      <span className="tabular">{t("common.range", { from, to, total })}</span>
      <div className="flex gap-1">
        <Button variant="outline" size="icon-sm" disabled={offset === 0} onClick={() => onChange(Math.max(0, offset - limit))} aria-label={t("common.previous")}>
          <ChevronLeft aria-hidden />
        </Button>
        <Button variant="outline" size="icon-sm" disabled={to >= total} onClick={() => onChange(offset + limit)} aria-label={t("common.next")}>
          <ChevronRight aria-hidden />
        </Button>
      </div>
    </div>
  );
}

export function Section({ title, description, children, actions }: { title: ReactNode; description?: ReactNode; children: ReactNode; actions?: ReactNode }) {
  return (
    <section className="grid gap-4 border-b py-6 first:pt-0 last:border-0 md:grid-cols-[16rem_1fr] md:gap-8">
      <div>
        <h2 className="font-semibold">{title}</h2>
        {description && <p className="mt-1 text-sm text-muted-foreground text-pretty">{description}</p>}
        {actions && <div className="mt-3">{actions}</div>}
      </div>
      <div className="min-w-0">{children}</div>
    </section>
  );
}
