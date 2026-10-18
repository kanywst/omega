import type { LucideIcon } from "lucide-react";
import { FileCode, FileText, Globe, KeyRound, ScrollText, ShieldCheck } from "lucide-react";

export type NavItem = {
  href: string;
  label: string;
  shortcut: string;
  desc: string;
  icon: LucideIcon;
};

export const NAV: NavItem[] = [
  {
    href: "/",
    label: "Overview",
    shortcut: "g h",
    desc: "Control plane status",
    icon: ShieldCheck,
  },
  { href: "/domains", label: "Domains", shortcut: "g d", desc: "SPIFFE namespaces", icon: Globe },
  {
    href: "/svid",
    label: "SVIDs",
    shortcut: "g s",
    desc: "Recently issued X.509 / JWT",
    icon: KeyRound,
  },
  {
    href: "/policy",
    label: "Decisions",
    shortcut: "g p",
    desc: "AuthZEN decisions",
    icon: ScrollText,
  },
  {
    href: "/policies",
    label: "Policies",
    shortcut: "g c",
    desc: "Cedar policies, read-only",
    icon: FileCode,
  },
  { href: "/audit", label: "Audit", shortcut: "g a", desc: "Tamper-evident chain", icon: FileText },
  {
    href: "/bundle",
    label: "Bundle",
    shortcut: "g b",
    desc: "Trust bundle export",
    icon: ShieldCheck,
  },
];
