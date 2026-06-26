"use client";

import { useRouter } from "next/navigation";
import { useCallback, useEffect, useState } from "react";
import { omega } from "@/lib/omega";
import { useGlobalShortcuts } from "@/lib/shortcuts";
import { CommandPalette } from "./command-palette";
import { NAV } from "./nav-items";
import { Sidebar } from "./sidebar";
import { Topbar } from "./topbar";

export function AppShell({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [health, setHealth] = useState<"ok" | "down" | "unknown">("unknown");

  useEffect(() => {
    let cancelled = false;
    const tick = () => {
      omega
        .health()
        .then((ok) => !cancelled && setHealth(ok ? "ok" : "down"))
        .catch(() => !cancelled && setHealth("down"));
    };
    tick();
    const id = setInterval(tick, 5000);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, []);

  const handlers = useCallback(() => {
    const map: Record<string, () => void> = {
      "mod+k": () => setPaletteOpen((s) => !s),
    };
    for (const item of NAV) {
      map[item.shortcut] = () => router.push(item.href);
    }
    return map;
  }, [router]);

  useGlobalShortcuts(handlers());

  return (
    <div className="flex h-screen min-w-0">
      <Sidebar />
      <div className="flex flex-1 flex-col overflow-hidden">
        <Topbar onPalette={() => setPaletteOpen(true)} health={health} />
        <main className="flex-1 overflow-y-auto bg-[var(--color-bg)]">
          <div className="mx-auto max-w-5xl px-8 py-8">{children}</div>
        </main>
      </div>
      <CommandPalette open={paletteOpen} onOpenChange={setPaletteOpen} />
    </div>
  );
}
