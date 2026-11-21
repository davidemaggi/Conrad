import type { ReactNode } from "react";
import { Tabs as T } from "radix-ui";
import { Info } from "lucide-react";
import { CodeBlock } from "@/components/common";
import { cn } from "@/lib/utils";

export interface GuideStep {
  title: ReactNode;
  code?: string;
  filename?: string;
}
export interface GuideEntry {
  id: string;
  label: string;
  hint?: string;
  steps: GuideStep[];
  note?: ReactNode;
}

/** Vertical tab list of platforms/clients with numbered steps and copyable snippets. */
export function Guide({ entries, value, onValueChange, label }: { entries: GuideEntry[]; value: string; onValueChange: (v: string) => void; label: string }) {
  return (
    <T.Root value={value} onValueChange={onValueChange} orientation="vertical" className="grid gap-6 md:grid-cols-[13rem_1fr]">
      <T.List aria-label={label} className="flex gap-1 overflow-x-auto pb-1 [scrollbar-width:thin] md:flex-col md:overflow-visible md:pb-0">
        {entries.map((e) => (
          <T.Trigger
            key={e.id}
            value={e.id}
            className={cn(
              "shrink-0 rounded-md px-3 py-2 text-left text-sm text-muted-foreground transition-colors hover:bg-muted hover:text-foreground",
              "data-[state=active]:bg-primary/10 data-[state=active]:font-medium data-[state=active]:text-primary",
            )}
          >
            {e.label}
            {e.hint && <span className="hidden text-xs font-normal text-muted-foreground md:block">{e.hint}</span>}
          </T.Trigger>
        ))}
      </T.List>
      {entries.map((e) => (
        <T.Content key={e.id} value={e.id} className="min-w-0 focus-visible:outline-none anim-fade">
          <ol className="grid gap-5">
            {e.steps.map((s, i) => (
              <li key={i} className="grid grid-cols-[1.75rem_1fr] gap-x-3 gap-y-2">
                <span className="flex size-7 items-center justify-center rounded-full bg-primary text-xs font-semibold text-primary-foreground tabular" aria-hidden>{i + 1}</span>
                <div className="self-center text-sm text-pretty">{s.title}</div>
                {s.code && <CodeBlock code={s.code} filename={s.filename} className="col-start-2" />}
              </li>
            ))}
          </ol>
          {e.note && (
            <p className="mt-5 flex gap-2 rounded-md border border-info/30 bg-info/5 px-3 py-2 text-sm">
              <Info className="mt-0.5 size-4 shrink-0 text-info" aria-hidden />
              <span>{e.note}</span>
            </p>
          )}
        </T.Content>
      ))}
    </T.Root>
  );
}
