import type { ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { Languages, Monitor, Moon, Sun } from "lucide-react";
import { Logo } from "@/components/Logo";
import { Button } from "@/components/ui/button";
import { DropdownMenu, DropdownMenuContent, DropdownMenuRadioGroup, DropdownMenuRadioItem, DropdownMenuTrigger } from "@/components/ui/misc";
import { useTheme, type Theme } from "@/lib/theme";
import { LANGUAGES } from "@/i18n";

export function PrefsButtons() {
  const { t, i18n } = useTranslation();
  const { theme, setTheme } = useTheme();
  const ThemeIcon = theme === "dark" ? Moon : theme === "light" ? Sun : Monitor;
  return (
    <div className="flex gap-1">
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="ghost" size="sm" aria-label={t("prefs.language")}>
            <Languages aria-hidden /> {LANGUAGES.find((l) => l.code === i18n.resolvedLanguage)?.label}
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end">
          <DropdownMenuRadioGroup value={i18n.resolvedLanguage} onValueChange={(v) => void i18n.changeLanguage(v)}>
            {LANGUAGES.map((l) => (
              <DropdownMenuRadioItem key={l.code} value={l.code} lang={l.code}>{l.label}</DropdownMenuRadioItem>
            ))}
          </DropdownMenuRadioGroup>
        </DropdownMenuContent>
      </DropdownMenu>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="ghost" size="icon-sm" aria-label={t("prefs.theme")}>
            <ThemeIcon aria-hidden />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end">
          <DropdownMenuRadioGroup value={theme} onValueChange={(v) => setTheme(v as Theme)}>
            <DropdownMenuRadioItem value="light"><Sun aria-hidden /> {t("prefs.light")}</DropdownMenuRadioItem>
            <DropdownMenuRadioItem value="dark"><Moon aria-hidden /> {t("prefs.dark")}</DropdownMenuRadioItem>
            <DropdownMenuRadioItem value="system"><Monitor aria-hidden /> {t("prefs.system")}</DropdownMenuRadioItem>
          </DropdownMenuRadioGroup>
        </DropdownMenuContent>
      </DropdownMenu>
    </div>
  );
}

/** Split layout: green brand panel with the stamp on the left, form on the right. */
export function AuthLayout({ children, wide }: { children: ReactNode; wide?: boolean }) {
  const { t } = useTranslation();
  return (
    <div className="grid min-h-dvh lg:grid-cols-[minmax(20rem,28rem)_1fr]">
      <aside className="relative hidden overflow-hidden bg-sidebar p-10 text-sidebar-foreground lg:flex lg:flex-col">
        <div className="flex items-center gap-3">
          <Logo size={36} tone="inverse" simple />
          <span className="text-lg font-bold tracking-tight">Conrad</span>
        </div>
        <div className="my-auto">
          <Logo size={220} tone="inverse" className="anim-stamp mx-auto drop-shadow-[0_8px_24px_rgb(0_0_0/0.25)]" />
          <p className="mt-10 text-2xl font-semibold leading-snug text-balance">{t("auth.heroTitle")}</p>
          <p className="mt-3 text-sm leading-relaxed text-sidebar-muted text-pretty">{t("auth.heroText")}</p>
        </div>
        <p className="text-xs text-sidebar-muted">{t("auth.heroFooter")}</p>
      </aside>
      <div className="flex flex-col">
        <div className="flex items-center justify-between p-4 sm:p-6">
          <div className="flex items-center gap-2 lg:invisible">
            <Logo size={32} simple />
            <span className="font-semibold">Conrad</span>
          </div>
          <PrefsButtons />
        </div>
        <main id="main" className={`mx-auto flex w-full flex-1 flex-col justify-center px-4 pb-12 sm:px-6 ${wide ? "max-w-2xl" : "max-w-sm"}`}>
          {children}
        </main>
      </div>
    </div>
  );
}
