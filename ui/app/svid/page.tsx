"use client";

import { useQuery } from "@tanstack/react-query";
import { Mono } from "@/components/data/code";
import { EmptyState } from "@/components/data/empty-state";
import { StatusPill } from "@/components/data/status-pill";
import { PageHeader } from "@/components/shell/page-header";
import { omega } from "@/lib/omega";

export default function SvidPage() {
  const events = useQuery({ queryKey: ["audit", 200], queryFn: () => omega.listAudit(200) });

  const issued =
    events.data?.filter((e) => e.kind === "svid.issue.x509" || e.kind === "svid.issue.jwt") ?? [];

  return (
    <>
      <PageHeader
        kicker="Identity"
        title="SVIDs"
        description="X.509 and JWT SVIDs the control plane has signed. Reconstructed from the audit chain."
      />

      {events.data && issued.length === 0 && (
        <EmptyState
          title="No SVIDs issued yet."
          hint="Run the demo or call the API directly."
          command="make demo"
        />
      )}
      {issued.length > 0 && (
        <ol className="space-y-1.5">
          {[...issued].reverse().map((ev) => (
            <li
              key={ev.seq}
              className="flex items-center gap-3 border-[var(--color-line)] border-b py-2.5 text-[13px] last:border-0"
            >
              <span className="w-12 shrink-0 font-mono text-[11px] text-[var(--color-fg-subtle)]">
                #{ev.seq}
              </span>
              <StatusPill tone={ev.kind === "svid.issue.jwt" ? "warn" : "neutral"}>
                {ev.kind === "svid.issue.jwt" ? "JWT" : "X.509"}
              </StatusPill>
              <Mono className="flex-1 truncate">{ev.subject}</Mono>
              <span className="font-mono text-[11px] text-[var(--color-fg-subtle)]">
                {ev.ts.replace("T", " ").slice(0, 19)}
              </span>
            </li>
          ))}
        </ol>
      )}
    </>
  );
}
