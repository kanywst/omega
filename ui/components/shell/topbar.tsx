"use client";

import { Search } from "lucide-react";
import { Kbd } from "@/components/ui/kbd";

export function Topbar({
  onPalette,
  health,
}: {
  onPalette: () => void;
  health: "ok" | "down" | "unknown";
}) {
  const healthLabel = health === "ok" ? "online" : health === "down" ? "offline" : "checking";
  const healthColor =
    health === "ok"
      ? "var(--color-ok)"
      : health === "down"
        ? "var(--color-err)"
        : "var(--color-fg-subtle)";
  return (
    <header className="flex h-12 shrink-0 items-center gap-3 border-[var(--color-line)] border-b bg-[var(--color-bg)] px-4">
      <button
        type="button"
        onClick={onPalette}
        className="group flex h-8 flex-1 max-w-md items-center gap-2 rounded-[6px] border border-[var(--color-line)] bg-[var(--color-bg-raised)] px-2.5 text-left text-[13px] text-[var(--color-fg-subtle)] transition-colors hover:border-[var(--color-line-strong)] hover:text-[var(--color-fg-muted)]"
      >
        <Search size={13} strokeWidth={1.75} />
        <span>Jump to or run</span>
        <Kbd className="ml-auto">⌘K</Kbd>
      </button>

      <div className="ml-auto flex items-center gap-2 font-mono text-[11px] text-[var(--color-fg-subtle)]">
        <span
          className="h-1.5 w-1.5 rounded-full"
          style={{ background: healthColor }}
          aria-hidden
        />
        <span>control-plane {healthLabel}</span>
      </div>
    </header>
  );
}
