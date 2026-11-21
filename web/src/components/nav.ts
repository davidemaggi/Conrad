import { BadgeCheck, BookOpen, Building2, FileBadge, Gauge, Bell, Settings, TerminalSquare, Users, ScrollText, type LucideIcon } from "lucide-react";

export interface NavItem {
  to: string;
  key: string;
  icon: LucideIcon;
  end?: boolean;
}

export const NAV: { group: string; items: NavItem[] }[] = [
  { group: "overview", items: [{ to: "/", key: "dashboard", icon: Gauge, end: true }] },
  {
    group: "pki",
    items: [
      { to: "/authorities", key: "authorities", icon: Building2 },
      { to: "/certificates", key: "certificates", icon: FileBadge },
      { to: "/accounts", key: "accounts", icon: Users },
    ],
  },
  {
    group: "guides",
    items: [
      { to: "/install", key: "install", icon: BadgeCheck },
      { to: "/clients", key: "clients", icon: TerminalSquare },
    ],
  },
  {
    group: "system",
    items: [
      { to: "/notifications", key: "notifications", icon: Bell },
      { to: "/audit", key: "audit", icon: ScrollText },
      { to: "/settings", key: "settings", icon: Settings },
    ],
  },
];

export const DOCS_ICON = BookOpen;
