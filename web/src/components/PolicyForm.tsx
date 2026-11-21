import { useTranslation } from "react-i18next";
import type { Policy } from "@/lib/types";
import { CHALLENGES, KEY_TYPES } from "@/lib/types";
import { Field, FieldLabel } from "@/components/ui/field";
import { Input, Textarea } from "@/components/ui/input";
import { Checkbox, Switch } from "@/components/ui/misc";

export const DEFAULT_POLICY: Policy = {
  allowedDomains: ["*.home.lab", "*.lan", "*.internal"],
  allowWildcards: true,
  allowIPs: false,
  defaultValidityDays: 90,
  maxValidityDays: 397,
  keyTypes: [...KEY_TYPES],
  challenges: [...CHALLENGES],
  requireEAB: false,
  clientAuth: false,
  rateLimits: { ordersPerAccountPerHour: 300, newAccountsPerIPPerHour: 50 },
};

export const lines = (s: string) => s.split(/[\n,]/).map((x) => x.trim()).filter(Boolean);

function ToggleRow({ id, label, hint, checked, onChange }: { id: string; label: string; hint?: string; checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <div className="flex items-start justify-between gap-4 py-3">
      <div>
        <FieldLabel htmlFor={id}>{label}</FieldLabel>
        {hint && <p className="mt-1 text-[13px] text-muted-foreground" id={`${id}-hint`}>{hint}</p>}
      </div>
      <Switch id={id} checked={checked} onCheckedChange={onChange} aria-describedby={hint ? `${id}-hint` : undefined} />
    </div>
  );
}

function CheckGroup({ legend, options, value, onChange }: { legend: string; options: readonly string[]; value: string[]; onChange: (v: string[]) => void }) {
  return (
    <fieldset className="grid gap-2">
      <legend className="mb-2 text-sm font-medium">{legend}</legend>
      <div className="flex flex-wrap gap-2">
        {options.map((o) => {
          const on = value.includes(o);
          return (
            <label key={o} className="flex h-9 cursor-pointer items-center gap-2 rounded-md border bg-card px-3 font-mono text-[12.5px] has-[:focus-visible]:outline-2 has-[:focus-visible]:outline-ring">
              <Checkbox checked={on} onCheckedChange={(c) => onChange(c ? [...value, o] : value.filter((x) => x !== o))} />
              {o}
            </label>
          );
        })}
      </div>
    </fieldset>
  );
}

export function PolicyForm({ value, onChange, compact }: { value: Policy; onChange: (p: Policy) => void; compact?: boolean }) {
  const { t } = useTranslation();
  const set = <K extends keyof Policy>(k: K, v: Policy[K]) => onChange({ ...value, [k]: v });
  return (
    <div className="grid gap-5">
      <Field label={t("policy.allowedDomains")} hint={t("policy.allowedDomainsHint")}>
        <Textarea
          className="font-mono text-[13px]"
          rows={4}
          defaultValue={value.allowedDomains.join("\n")}
          onBlur={(e) => set("allowedDomains", lines(e.target.value))}
          spellCheck={false}
        />
      </Field>
      <div className="divide-y rounded-lg border bg-card px-4">
        <ToggleRow id="p-wild" label={t("policy.allowWildcards")} hint={t("policy.allowWildcardsHint")} checked={value.allowWildcards} onChange={(v) => set("allowWildcards", v)} />
        <ToggleRow id="p-ip" label={t("policy.allowIPs")} hint={t("policy.allowIPsHint")} checked={value.allowIPs} onChange={(v) => set("allowIPs", v)} />
        <ToggleRow id="p-eab" label={t("policy.requireEAB")} hint={t("policy.requireEABHint")} checked={value.requireEAB} onChange={(v) => set("requireEAB", v)} />
        {!compact && <ToggleRow id="p-client" label={t("policy.clientAuth")} hint={t("policy.clientAuthHint")} checked={value.clientAuth} onChange={(v) => set("clientAuth", v)} />}
      </div>
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label={t("policy.defaultValidity")} hint={t("policy.days")}>
          <Input type="number" inputMode="numeric" min={1} value={value.defaultValidityDays} onChange={(e) => set("defaultValidityDays", Number(e.target.value))} />
        </Field>
        <Field label={t("policy.maxValidity")} hint={t("policy.days")}>
          <Input type="number" inputMode="numeric" min={1} value={value.maxValidityDays} onChange={(e) => set("maxValidityDays", Number(e.target.value))} />
        </Field>
      </div>
      {!compact && (
        <>
          <CheckGroup legend={t("policy.keyTypes")} options={KEY_TYPES} value={value.keyTypes} onChange={(v) => set("keyTypes", v)} />
          <CheckGroup legend={t("policy.challenges")} options={CHALLENGES} value={value.challenges} onChange={(v) => set("challenges", v)} />
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label={t("policy.ordersPerHour")} hint={t("policy.zeroUnlimited")}>
              <Input
                type="number"
                inputMode="numeric"
                min={0}
                value={value.rateLimits.ordersPerAccountPerHour}
                onChange={(e) => set("rateLimits", { ...value.rateLimits, ordersPerAccountPerHour: Number(e.target.value) })}
              />
            </Field>
            <Field label={t("policy.accountsPerHour")} hint={t("policy.zeroUnlimited")}>
              <Input
                type="number"
                inputMode="numeric"
                min={0}
                value={value.rateLimits.newAccountsPerIPPerHour}
                onChange={(e) => set("rateLimits", { ...value.rateLimits, newAccountsPerIPPerHour: Number(e.target.value) })}
              />
            </Field>
          </div>
        </>
      )}
    </div>
  );
}
