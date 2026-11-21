import { useEffect, useState, type ReactNode } from "react";
import { NavLink, useLocation } from "react-router";
import { useTranslation } from "react-i18next";
import { Dialog as D } from "radix-ui";
import { Command, Languages, LogOut, Menu, Monitor, Moon, Sun, UserRound, X } from "lucide-react";
import { NAV } from "@/components/nav";
import { Logo } from "@/components/Logo";
import { CALockedBanner } from "@/components/CALockedBanner";
import { CommandMenu } from "@/components/CommandMenu";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/misc";
import { useTheme, type Theme } from "@/lib/theme";
import { useLogout } from "@/lib/session";
import { LANGUAGES } from "@/i18n";
import { cn } from "@/lib/utils";
import type { Me, SystemStatus } from "@/lib/types";
import { Link } from "react-router";

function SidebarNav({ onNavigate, version }: { onNavigate?: () => void; version?: string }) {
  const { t } = useTranslation();
  return (
    <div className="flex h-full flex-col bg-sidebar text-sidebar-foreground">
      <Link to="/" onClick={onNavigate} className="flex items-center gap-3 px-5 pb-5 pt-5 outline-offset-[-2px]">
        <Logo size={44} tone="inverse" />
        <div className="leading-tight">
          <div className="text-lg font-bold tracking-tight">Conrad</div>
          <div className="text-[11px] uppercase tracking-[0.14em] text-sidebar-muted">{t("app.tagline")}</div>
        </div>
      </Link>
      <nav aria-label={t("nav.label")} className="flex-1 overflow-y-auto px-3 pb-4">
        {NAV.map((g) => (
          <div key={g.group} className="mt-4 first:mt-1">
            <div className="px-3 pb-1.5 text-[11px] font-semibold uppercase tracking-[0.14em] text-sidebar-muted">{t(`nav.groups.${g.group}`)}</div>
            <ul className="grid gap-0.5">
              {g.items.map((it) => (
                <li key={it.to}>
                  <NavLink
                    to={it.to}
                    end={it.end}
                    onClick={onNavigate}
                    className={({ isActive }) =>
                      cn(
                        "flex h-10 items-center gap-3 rounded-md px-3 text-sm font-medium transition-colors outline-offset-[-2px] focus-visible:outline-sidebar-active",
                        isActive ? "bg-sidebar-active text-sidebar-active-foreground shadow-sm" : "text-sidebar-foreground/90 hover:bg-sidebar-hover hover:text-sidebar-foreground",
                      )
                    }
                  >
                    <it.icon className="size-[18px] shrink-0" aria-hidden />
                    {t(`nav.${it.key}`)}
                  </NavLink>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </nav>
      <div className="border-t border-sidebar-border px-5 py-3 text-[11px] text-sidebar-muted">
        Conrad {version ? `v${version.replace(/^v/, "")}` : ""}
      </div>
    </div>
  );
}

export function AppShell({ me, status, children }: { me: Me; status: SystemStatus; children: ReactNode }) {
  const { t, i18n } = useTranslation();
  const { theme, setTheme } = useTheme();
  const logout = useLogout();
  const [drawer, setDrawer] = useState(false);
  const [cmd, setCmd] = useState(false);
  const loc = useLocation();

  useEffect(() => setDrawer(false), [loc.pathname]);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setCmd((c) => !c);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const ThemeIcon = theme === "dark" ? Moon : theme === "light" ? Sun : Monitor;
  const isMac = typeof navigator !== "undefined" && /Mac|iPhone|iPad/.test(navigator.platform);

  return (
    <div className="min-h-dvh lg:grid lg:grid-cols-[16.5rem_1fr]">
      <a href="#main" className="sr-only z-[100] rounded-md bg-primary px-3 py-2 text-primary-foreground focus:not-sr-only focus:fixed focus:left-3 focus:top-3">
        {t("common.skipToContent")}
      </a>
      <aside className="sticky top-0 hidden h-dvh lg:block">
        <SidebarNav version={status.version} />
      </aside>
      <D.Root open={drawer} onOpenChange={setDrawer}>
        <D.Portal>
          <D.Overlay className="anim-fade fixed inset-0 z-40 bg-black/50 lg:hidden" />
          <D.Content className="anim-left fixed inset-y-0 left-0 z-50 w-[17rem] max-w-[85vw] shadow-2xl lg:hidden">
            <D.Title className="sr-only">{t("nav.label")}</D.Title>
            <D.Description className="sr-only">{t("nav.label")}</D.Description>
            <SidebarNav onNavigate={() => setDrawer(false)} version={status.version} />
            <D.Close className="absolute right-2 top-2 flex size-10 items-center justify-center rounded-md text-sidebar-foreground hover:bg-sidebar-hover" aria-label={t("common.close")}>
              <X className="size-5" aria-hidden />
            </D.Close>
          </D.Content>
        </D.Portal>
      </D.Root>

      <div className="flex min-w-0 flex-col">
        <header className="sticky top-0 z-30 flex h-14 items-center gap-2 border-b bg-background/90 px-3 backdrop-blur supports-[backdrop-filter]:bg-background/75 sm:px-5">
          <Button variant="ghost" size="icon" className="lg:hidden" onClick={() => setDrawer(true)} aria-label={t("nav.open")}>
            <Menu aria-hidden />
          </Button>
          <Link to="/" className="flex items-center gap-2 lg:hidden">
            <Logo size={28} simple />
            <span className="font-semibold">Conrad</span>
          </Link>
          <button
            onClick={() => setCmd(true)}
            className="ml-auto hidden h-9 w-64 items-center gap-2 rounded-md border bg-card px-3 text-sm text-muted-foreground shadow-xs hover:bg-accent sm:flex lg:ml-0"
          >
            <Command className="size-4" aria-hidden />
            <span className="flex-1 text-left">{t("command.placeholderShort")}</span>
            <kbd className="rounded border bg-muted px-1.5 font-mono text-[11px]">{isMac ? "⌘K" : "Ctrl K"}</kbd>
          </button>
          <div className="ml-auto flex items-center gap-1">
            <Button variant="ghost" size="icon" className="sm:hidden" onClick={() => setCmd(true)} aria-label={t("command.open")}>
              <Command aria-hidden />
            </Button>
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="ghost" size="icon" aria-label={t("prefs.language")}>
                  <Languages aria-hidden />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                <DropdownMenuLabel>{t("prefs.language")}</DropdownMenuLabel>
                <DropdownMenuRadioGroup value={i18n.resolvedLanguage} onValueChange={(v) => void i18n.changeLanguage(v)}>
                  {LANGUAGES.map((l) => (
                    <DropdownMenuRadioItem key={l.code} value={l.code} lang={l.code}>{l.label}</DropdownMenuRadioItem>
                  ))}
                </DropdownMenuRadioGroup>
              </DropdownMenuContent>
            </DropdownMenu>
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="ghost" size="icon" aria-label={t("prefs.theme")}>
                  <ThemeIcon aria-hidden />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                <DropdownMenuLabel>{t("prefs.theme")}</DropdownMenuLabel>
                <DropdownMenuRadioGroup value={theme} onValueChange={(v) => setTheme(v as Theme)}>
                  <DropdownMenuRadioItem value="light"><Sun aria-hidden /> {t("prefs.light")}</DropdownMenuRadioItem>
                  <DropdownMenuRadioItem value="dark"><Moon aria-hidden /> {t("prefs.dark")}</DropdownMenuRadioItem>
                  <DropdownMenuRadioItem value="system"><Monitor aria-hidden /> {t("prefs.system")}</DropdownMenuRadioItem>
                </DropdownMenuRadioGroup>
              </DropdownMenuContent>
            </DropdownMenu>
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="ghost" className="h-10 gap-2 px-2" aria-label={t("prefs.account")}>
                  <span className="flex size-7 items-center justify-center rounded-full bg-primary text-xs font-bold uppercase text-primary-foreground">
                    {me.admin.username.slice(0, 1)}
                  </span>
                  <span className="hidden max-w-32 truncate text-sm md:inline">{me.admin.username}</span>
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                <DropdownMenuLabel>
                  {t("prefs.signedInAs")} <span className="font-medium text-foreground">{me.admin.username}</span>
                  <span className="block">{t(`auth.method.${me.method}`, { defaultValue: me.method })}</span>
                </DropdownMenuLabel>
                <DropdownMenuSeparator />
                <DropdownMenuItem asChild>
                  <Link to="/settings"><UserRound aria-hidden /> {t("settings.profile")}</Link>
                </DropdownMenuItem>
                <DropdownMenuSeparator />
                <DropdownMenuItem onSelect={() => void logout()} className="text-destructive [&_svg]:text-destructive">
                  <LogOut aria-hidden /> {t("auth.logout")}
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        </header>
        {status.caLocked && <CALockedBanner />}
        <main id="main" tabIndex={-1} className="mx-auto w-full max-w-7xl flex-1 px-4 py-6 outline-none sm:px-6 lg:px-8 lg:py-8">
          {children}
        </main>
      </div>
      <CommandMenu open={cmd} onOpenChange={setCmd} />
    </div>
  );
}
