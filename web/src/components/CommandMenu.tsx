import { useNavigate } from "react-router";
import { useTranslation } from "react-i18next";
import { Command } from "cmdk";
import { Dialog as D } from "radix-ui";
import { useQuery } from "@tanstack/react-query";
import { Building2, FileBadge, Plus, Search } from "lucide-react";
import { NAV } from "@/components/nav";
import { api } from "@/lib/api";
import type { Authority } from "@/lib/types";

const item =
  "flex min-h-10 cursor-pointer select-none items-center gap-3 rounded-md px-3 text-sm aria-selected:bg-accent aria-selected:text-accent-foreground [&_svg]:size-4 [&_svg]:text-muted-foreground";
const group = "[&_[cmdk-group-heading]]:px-3 [&_[cmdk-group-heading]]:pb-1 [&_[cmdk-group-heading]]:pt-3 [&_[cmdk-group-heading]]:text-[11px] [&_[cmdk-group-heading]]:font-semibold [&_[cmdk-group-heading]]:uppercase [&_[cmdk-group-heading]]:tracking-[0.14em] [&_[cmdk-group-heading]]:text-muted-foreground";

export function CommandMenu({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const { t } = useTranslation();
  const nav = useNavigate();
  const auths = useQuery({ queryKey: ["authorities"], queryFn: () => api.get<{ items: Authority[] }>("/authorities"), enabled: open });
  const go = (to: string) => {
    onOpenChange(false);
    nav(to);
  };
  return (
    <D.Root open={open} onOpenChange={onOpenChange}>
      <D.Portal>
        <D.Overlay className="anim-fade fixed inset-0 z-50 bg-black/50" />
        <D.Content className="anim-down fixed left-1/2 top-[12vh] z-50 w-[calc(100vw-2rem)] max-w-xl -translate-x-1/2 overflow-hidden rounded-xl border bg-popover text-popover-foreground shadow-2xl">
          <D.Title className="sr-only">{t("command.open")}</D.Title>
          <D.Description className="sr-only">{t("command.placeholder")}</D.Description>
          <Command label={t("command.open")} loop>
            <div className="flex items-center gap-2 border-b px-3">
              <Search className="size-4 text-muted-foreground" aria-hidden />
              <Command.Input autoFocus placeholder={t("command.placeholder")} className="h-12 flex-1 bg-transparent text-base outline-none placeholder:text-muted-foreground sm:text-sm" />
            </div>
            <Command.List className="max-h-[60vh] overflow-y-auto p-2">
              <Command.Empty className="px-3 py-8 text-center text-sm text-muted-foreground">{t("command.empty")}</Command.Empty>
              <Command.Group heading={t("command.actions")} className={group}>
                <Command.Item className={item} onSelect={() => go("/certificates?issue=1")}><Plus aria-hidden /> {t("certs.issue")}</Command.Item>
                <Command.Item className={item} onSelect={() => go("/authorities?create=1")}><Plus aria-hidden /> {t("authorities.create")}</Command.Item>
                <Command.Item className={item} onSelect={() => go("/certificates")}><FileBadge aria-hidden /> {t("command.searchCerts")}</Command.Item>
              </Command.Group>
              <Command.Group heading={t("command.pages")} className={group}>
                {NAV.flatMap((g) => g.items).map((it) => (
                  <Command.Item key={it.to} className={item} value={t(`nav.${it.key}`)} onSelect={() => go(it.to)}>
                    <it.icon aria-hidden /> {t(`nav.${it.key}`)}
                  </Command.Item>
                ))}
              </Command.Group>
              {!!auths.data?.items.length && (
                <Command.Group heading={t("nav.authorities")} className={group}>
                  {auths.data.items.map((a) => (
                    <Command.Item key={a.id} className={item} value={`${a.name} ${a.slug}`} onSelect={() => go(`/authorities/${a.id}`)}>
                      <Building2 aria-hidden /> {a.name}
                      <span className="ml-auto font-mono text-xs text-muted-foreground">{a.kind === "root" ? "root" : a.slug}</span>
                    </Command.Item>
                  ))}
                </Command.Group>
              )}
            </Command.List>
          </Command>
        </D.Content>
      </D.Portal>
    </D.Root>
  );
}
