"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { Kbd } from "@/components/ui/kbd";
import { cn } from "@/lib/cn";
import { NAV } from "./nav-items";

export function Sidebar() {
  const pathname = usePathname();
  return (
    <aside className="flex h-screen w-[220px] shrink-0 flex-col border-[var(--color-line)] border-r bg-[var(--color-bg)]">
      <div className="flex h-12 items-center gap-2 px-4">
        <span className="grid h-5 w-5 place-items-center rounded-[5px] bg-[var(--color-accent)] font-mono text-[12px] text-[var(--color-accent-fg)]">
          Ω
        </span>
        <span className="font-medium text-[13px] text-[var(--color-fg)] tracking-tight">Omega</span>
        <span className="ml-auto font-mono text-[10.5px] text-[var(--color-fg-subtle)] uppercase tracking-wider">
          pre-alpha
        </span>
      </div>

      <nav className="flex-1 px-2 py-2">
        {NAV.map((item) => {
          const active = item.href === "/" ? pathname === "/" : pathname.startsWith(item.href);
          return (
            <Link
              key={item.href}
              href={item.href}
              className={cn(
                "group flex h-7 items-center gap-2 rounded-[5px] px-2 text-[13px] transition-colors",
                active
                  ? "bg-[var(--color-bg-muted)] text-[var(--color-fg)]"
                  : "text-[var(--color-fg-muted)] hover:bg-[var(--color-bg-raised)] hover:text-[var(--color-fg)]",
              )}
            >
              <item.icon
                size={14}
                strokeWidth={1.75}
                className={cn(
                  active ? "text-[var(--color-accent)]" : "text-[var(--color-fg-subtle)]",
                )}
              />
              <span className="flex-1 tracking-tight">{item.label}</span>
              <Kbd className="opacity-0 group-hover:opacity-100">{item.shortcut}</Kbd>
            </Link>
          );
        })}
      </nav>

      <div className="border-[var(--color-line)] border-t px-3 py-3 text-[11px] text-[var(--color-fg-subtle)]">
        <div className="font-mono">trust-domain</div>
        <div className="mt-0.5 font-mono text-[var(--color-fg-muted)]">omega.local</div>
      </div>
    </aside>
  );
}
