import { useMemo, useState, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, ArrowRight, Check, Download, Monitor, Moon, Sun } from "lucide-react";
import { api, setCsrf } from "@/lib/api";
import type { Policy, SystemStatus } from "@/lib/types";
import { CA_ALGORITHMS } from "@/lib/types";
import { AuthLayout } from "@/components/AuthLayout";
import { Button } from "@/components/ui/button";
import { Input, PasswordInput, Textarea } from "@/components/ui/input";
import { Field } from "@/components/ui/field";
import { Select } from "@/components/ui/select";
import { ErrorAlert, KV } from "@/components/common";
import { DEFAULT_POLICY, PolicyForm, lines } from "@/components/PolicyForm";
import { Logo } from "@/components/Logo";
import { LANGUAGES } from "@/i18n";
import { useTheme, type Theme } from "@/lib/theme";
import { cn, validSlug } from "@/lib/utils";
import { useTitle } from "@/App";

const STEPS = ["welcome", "admin", "ca", "policy", "review"] as const;

function Choice({ selected, onClick, title, text, icon }: { selected: boolean; onClick: () => void; title: string; text?: string; icon?: ReactNode }) {
  return (
    <button
      type="button"
      role="radio"
      aria-checked={selected}
      onClick={onClick}
      className={cn(
        "flex items-start gap-3 rounded-lg border bg-card p-4 text-left transition-colors hover:bg-accent/60",
        selected && "border-primary ring-1 ring-primary",
      )}
    >
      {icon && <span className="mt-0.5 text-muted-foreground [&_svg]:size-5">{icon}</span>}
      <span className="flex-1">
        <span className="block text-sm font-medium">{title}</span>
        {text && <span className="mt-0.5 block text-[13px] text-muted-foreground">{text}</span>}
      </span>
      <span className={cn("mt-0.5 flex size-5 items-center justify-center rounded-full border", selected && "border-primary bg-primary text-primary-foreground")}>
        {selected && <Check className="size-3" strokeWidth={3} aria-hidden />}
      </span>
    </button>
  );
}

export default function Setup({ status }: { status: SystemStatus }) {
  const { t, i18n } = useTranslation();
  useTitle(t("setup.title"));
  const { theme, setTheme } = useTheme();
  const qc = useQueryClient();
  const hsm = status.keyProvider === "pkcs11";
  const [step, setStep] = useState(0);
  const [done, setDone] = useState(false);
  const [token, setToken] = useState(() => new URLSearchParams(location.search).get("token") ?? "");
  const [admin, setAdmin] = useState({ username: "admin", password: "", confirm: "" });
  const [mode, setMode] = useState<"generate" | "import">("generate");
  const [passphrase, setPassphrase] = useState({ value: "", confirm: "" });
  const [subject, setSubject] = useState({ commonName: "Conrad Root CA", organization: "Home Lab", country: "" });
  const [rootAlg, setRootAlg] = useState("ecdsa-p384");
  const [rootYears, setRootYears] = useState(20);
  const [constraints, setConstraints] = useState("");
  const [issuer, setIssuer] = useState({ slug: "default", name: "Default Issuer", algorithm: "ecdsa-p256", validityYears: 5 });
  const [pems, setPems] = useState({ rootCertPem: "", rootKeyPem: "", issuerCertPem: "", issuerKeyPem: "" });
  const [policy, setPolicy] = useState<Policy>(DEFAULT_POLICY);
  const [touched, setTouched] = useState(false);

  const errors = useMemo(() => {
    const e: Record<string, string> = {};
    if (step === 0 && !token.trim()) e.token = t("setup.errors.token");
    if (step === 1) {
      if (!admin.username.trim()) e.username = t("setup.errors.username");
      if (admin.password.length < 12) e.password = t("errors.auth.weak_password");
      else if (admin.password !== admin.confirm) e.confirm = t("setup.errors.mismatch");
    }
    if (step === 2) {
      if (!hsm && passphrase.value.length < 12) e.passphrase = t("setup.errors.passphrase");
      else if (!hsm && passphrase.value !== passphrase.confirm) e.passphraseConfirm = t("setup.errors.mismatch");
      if (hsm && !passphrase.value) e.passphrase = t("setup.errors.pin");
      if (!validSlug(issuer.slug)) e.slug = t("errors.issuer.invalid_slug");
      if (mode === "generate" && !subject.commonName.trim()) e.cn = t("setup.errors.cn");
      if (mode === "import" && (!pems.rootCertPem.trim() || !pems.issuerCertPem.trim() || !pems.issuerKeyPem.trim())) e.pems = t("setup.errors.pems");
    }
    return e;
  }, [step, token, admin, passphrase, issuer.slug, mode, subject.commonName, pems, hsm, t]);

  const m = useMutation({
    mutationFn: () =>
      api.post<{ csrfToken: string }>("/setup", {
        token: token.trim(),
        admin: { username: admin.username.trim(), password: admin.password, language: i18n.resolvedLanguage },
        ca: {
          mode,
          passphrase: passphrase.value,
          subject,
          algorithm: rootAlg,
          validityYears: rootYears,
          nameConstraints: lines(constraints),
          issuer,
          ...(mode === "import" ? pems : {}),
        },
        policy,
      }),
    onSuccess: (r) => {
      setCsrf(r.csrfToken);
      setDone(true);
    },
  });

  const next = () => {
    setTouched(true);
    if (Object.keys(errors).length) return;
    setTouched(false);
    if (step < STEPS.length - 1) setStep(step + 1);
    else m.mutate();
  };
  const err = (k: string) => (touched ? errors[k] : undefined);

  if (done) {
    return (
      <AuthLayout wide>
        <div className="text-center">
          <Logo size={120} className="anim-stamp mx-auto" />
          <h1 className="mt-6 text-2xl font-semibold tracking-tight">{t("setup.doneTitle")}</h1>
          <p className="mx-auto mt-2 max-w-md text-sm text-muted-foreground text-pretty">{t("setup.doneText")}</p>
          <div className="mt-8 flex flex-col justify-center gap-2 sm:flex-row">
            <Button asChild variant="outline">
              <a href="/roots/current.crt" download><Download aria-hidden /> {t("setup.downloadRoot")}</a>
            </Button>
            <Button
              onClick={async () => {
                await qc.invalidateQueries({ queryKey: ["status"] });
                window.history.replaceState(null, "", "/install");
              }}
            >
              {t("setup.continue")} <ArrowRight aria-hidden />
            </Button>
          </div>
        </div>
      </AuthLayout>
    );
  }

  return (
    <AuthLayout wide>
      <div className="stamp-label">{t("setup.eyebrow")}</div>
      <h1 className="mt-1 text-2xl font-semibold tracking-tight">{t(`setup.steps.${STEPS[step]}.title`)}</h1>
      <p className="mt-1.5 text-sm text-muted-foreground text-pretty">{t(`setup.steps.${STEPS[step]}.text`)}</p>

      <ol className="mt-6 flex gap-1.5" aria-label={t("setup.progress", { step: step + 1, total: STEPS.length })}>
        {STEPS.map((s, i) => (
          <li key={s} className="flex-1">
            <span className={cn("block h-1.5 rounded-full", i <= step ? "bg-primary" : "bg-muted")} />
            <span className={cn("mt-1.5 hidden text-xs sm:block", i === step ? "font-medium text-foreground" : "text-muted-foreground")} aria-current={i === step ? "step" : undefined}>
              {t(`setup.steps.${s}.short`)}
            </span>
          </li>
        ))}
      </ol>

      <form
        className="mt-6 grid gap-5"
        noValidate
        onSubmit={(e) => {
          e.preventDefault();
          next();
        }}
      >
        {step === 0 && (
          <>
            <Field label={t("setup.token")} hint={t("setup.tokenHint")} error={err("token")} required>
              <Input value={token} onChange={(e) => setToken(e.target.value)} className="font-mono" autoComplete="off" spellCheck={false} autoFocus />
            </Field>
            <fieldset>
              <legend className="mb-2 text-sm font-medium">{t("prefs.language")}</legend>
              <div role="radiogroup" className="grid gap-2 sm:grid-cols-2">
                {LANGUAGES.map((l) => (
                  <Choice key={l.code} selected={i18n.resolvedLanguage === l.code} onClick={() => void i18n.changeLanguage(l.code)} title={l.label} />
                ))}
              </div>
            </fieldset>
            <fieldset>
              <legend className="mb-2 text-sm font-medium">{t("prefs.theme")}</legend>
              <div role="radiogroup" className="grid gap-2 sm:grid-cols-3">
                {(["light", "dark", "system"] as Theme[]).map((th) => (
                  <Choice
                    key={th}
                    selected={theme === th}
                    onClick={() => setTheme(th)}
                    title={t(`prefs.${th}`)}
                    icon={th === "light" ? <Sun /> : th === "dark" ? <Moon /> : <Monitor />}
                  />
                ))}
              </div>
            </fieldset>
          </>
        )}

        {step === 1 && (
          <>
            <Field label={t("auth.username")} error={err("username")} required>
              <Input value={admin.username} onChange={(e) => setAdmin({ ...admin, username: e.target.value })} autoComplete="username" autoCapitalize="none" autoFocus />
            </Field>
            <Field label={t("auth.password")} hint={t("setup.passwordHint")} error={err("password")} required>
              <PasswordInput value={admin.password} onChange={(e) => setAdmin({ ...admin, password: e.target.value })} autoComplete="new-password" />
            </Field>
            <Field label={t("setup.confirmPassword")} error={err("confirm")} required>
              <PasswordInput value={admin.confirm} onChange={(e) => setAdmin({ ...admin, confirm: e.target.value })} autoComplete="new-password" />
            </Field>
          </>
        )}

        {step === 2 && (
          <>
            <div role="radiogroup" aria-label={t("setup.caMode")} className="grid gap-2 sm:grid-cols-2">
              <Choice selected={mode === "generate"} onClick={() => setMode("generate")} title={t("setup.generate")} text={t("setup.generateText")} />
              <Choice selected={mode === "import"} onClick={() => setMode("import")} title={t("setup.import")} text={t("setup.importText")} />
            </div>
            <div className="grid gap-4 sm:grid-cols-2">
              <Field label={hsm ? t("setup.pin") : t("setup.passphrase")} hint={hsm ? t("setup.pinHint") : t("setup.passphraseHint")} error={err("passphrase")} required>
                <PasswordInput value={passphrase.value} onChange={(e) => setPassphrase({ ...passphrase, value: e.target.value })} autoComplete="new-password" />
              </Field>
              {!hsm && (
                <Field label={t("setup.confirmPassphrase")} error={err("passphraseConfirm")} required>
                  <PasswordInput value={passphrase.confirm} onChange={(e) => setPassphrase({ ...passphrase, confirm: e.target.value })} autoComplete="new-password" />
                </Field>
              )}
            </div>
            {mode === "generate" ? (
              <>
                <h2 className="stamp-label -mb-2 mt-2">{t("setup.root")}</h2>
                <div className="grid gap-4 sm:grid-cols-2">
                  <Field label={t("ca.commonName")} error={err("cn")} required className="sm:col-span-2">
                    <Input value={subject.commonName} onChange={(e) => setSubject({ ...subject, commonName: e.target.value })} />
                  </Field>
                  <Field label={t("ca.organization")}>
                    <Input value={subject.organization} onChange={(e) => setSubject({ ...subject, organization: e.target.value })} />
                  </Field>
                  <Field label={t("ca.country")} hint={t("ca.countryHint")}>
                    <Input value={subject.country} maxLength={2} onChange={(e) => setSubject({ ...subject, country: e.target.value.toUpperCase() })} />
                  </Field>
                  <Field label={t("ca.algorithm")}>
                    <Select value={rootAlg} onValueChange={setRootAlg} options={CA_ALGORITHMS.map((a) => ({ value: a, label: a }))} />
                  </Field>
                  <Field label={t("ca.validityYears")}>
                    <Input type="number" min={1} max={50} value={rootYears} onChange={(e) => setRootYears(Number(e.target.value))} />
                  </Field>
                  <Field label={t("ca.nameConstraints")} hint={t("ca.nameConstraintsHint")} className="sm:col-span-2">
                    <Textarea rows={2} className="font-mono text-[13px]" value={constraints} onChange={(e) => setConstraints(e.target.value)} placeholder="home.lab" />
                  </Field>
                </div>
              </>
            ) : (
              <div className="grid gap-4">
                {(["rootCertPem", "rootKeyPem", "issuerCertPem", "issuerKeyPem"] as const).map((k) => (
                  <Field key={k} label={t(`setup.pem.${k}`)} hint={k === "rootKeyPem" ? t("setup.pem.rootKeyHint") : undefined} required={k !== "rootKeyPem"}>
                    <Textarea rows={4} className="font-mono text-[12px]" value={pems[k]} onChange={(e) => setPems({ ...pems, [k]: e.target.value })} placeholder="-----BEGIN …-----" spellCheck={false} />
                  </Field>
                ))}
                {err("pems") && <p role="alert" className="text-sm text-destructive">{err("pems")}</p>}
              </div>
            )}
            <h2 className="stamp-label -mb-2 mt-2">{t("setup.issuer")}</h2>
            <div className="grid gap-4 sm:grid-cols-2">
              <Field label={t("ca.slug")} hint={t("ca.slugHint")} error={err("slug")} required>
                <Input value={issuer.slug} onChange={(e) => setIssuer({ ...issuer, slug: e.target.value.toLowerCase() })} className="font-mono" />
              </Field>
              <Field label={t("ca.name")}>
                <Input value={issuer.name} onChange={(e) => setIssuer({ ...issuer, name: e.target.value })} />
              </Field>
              {mode === "generate" && (
                <>
                  <Field label={t("ca.algorithm")}>
                    <Select value={issuer.algorithm} onValueChange={(v) => setIssuer({ ...issuer, algorithm: v })} options={CA_ALGORITHMS.map((a) => ({ value: a, label: a }))} />
                  </Field>
                  <Field label={t("ca.validityYears")}>
                    <Input type="number" min={1} max={30} value={issuer.validityYears} onChange={(e) => setIssuer({ ...issuer, validityYears: Number(e.target.value) })} />
                  </Field>
                </>
              )}
            </div>
          </>
        )}

        {step === 3 && <PolicyForm value={policy} onChange={setPolicy} compact />}

        {step === 4 && (
          <div className="rounded-lg border bg-card p-5">
            <KV
              items={[
                [t("auth.username"), admin.username],
                [t("prefs.language"), LANGUAGES.find((l) => l.code === i18n.resolvedLanguage)?.label],
                [t("setup.caMode"), mode === "generate" ? t("setup.generate") : t("setup.import")],
                ...(mode === "generate"
                  ? ([
                      [t("setup.root"), `${subject.commonName} · ${rootAlg} · ${t("common.years", { count: rootYears })}`],
                    ] as [ReactNode, ReactNode][])
                  : []),
                [t("setup.issuer"), <span key="i"><code className="font-mono">{issuer.slug}</code> · {issuer.name}</span>],
                [t("policy.allowedDomains"), <code key="d" className="font-mono text-[12.5px]">{policy.allowedDomains.join(", ") || "—"}</code>],
                [t("policy.requireEAB"), policy.requireEAB ? t("common.yes") : t("common.no")],
              ]}
            />
          </div>
        )}

        <ErrorAlert error={m.error} />

        <div className="mt-2 flex items-center justify-between gap-2">
          <Button variant="ghost" onClick={() => setStep(step - 1)} disabled={step === 0 || m.isPending}>
            <ArrowLeft aria-hidden /> {t("common.back")}
          </Button>
          <Button type="submit" loading={m.isPending}>
            {step === STEPS.length - 1 ? t("setup.finish") : t("common.next")}
            {step < STEPS.length - 1 && <ArrowRight aria-hidden />}
          </Button>
        </div>
      </form>
    </AuthLayout>
  );
}
