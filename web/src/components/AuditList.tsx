import { useTranslation } from "react-i18next";
import type { AuditEntry } from "@/lib/types";
import { fmtDate, fmtRelative } from "@/lib/utils";

export function useActionLabel() {
  const { t } = useTranslation();
  return (a: string) => t(`audit.actions.${a.replace(/\./g, "_")}`, { defaultValue: a });
}

export function AuditList({ items }: { items: AuditEntry[] }) {
  const label = useActionLabel();
  return (
    <ol className="grid">
      {items.map((e) => (
        <li key={e.id} className="flex items-start gap-3 border-b py-2.5 last:border-0">
          <span className="mt-1.5 size-2 shrink-0 rounded-full bg-primary/70" aria-hidden />
          <div className="min-w-0 flex-1">
            <p className="text-sm">
              <span className="font-medium">{label(e.action)}</span>
              {e.target && <span className="ml-1.5 font-mono text-[12px] text-muted-foreground wrap-anywhere">{e.target}</span>}
            </p>
            <p className="text-xs text-muted-foreground">
              {e.actor} · <time dateTime={e.at} title={fmtDate(e.at, true)}>{fmtRelative(e.at)}</time>
            </p>
          </div>
        </li>
      ))}
    </ol>
  );
}
