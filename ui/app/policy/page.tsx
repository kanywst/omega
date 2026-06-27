"use client";

import { useQuery } from "@tanstack/react-query";
import { Mono } from "@/components/data/code";
import { EmptyState } from "@/components/data/empty-state";
import { StatusPill } from "@/components/data/status-pill";
import { PageHeader } from "@/components/shell/page-header";
import { omega } from "@/lib/omega";

export default function PolicyPage() {
  const events = useQuery({ queryKey: ["audit", 300], queryFn: () => omega.listAudit(300) });
  const decisions = events.data?.filter((e) => e.kind === "access.evaluate") ?? [];

  return (
    <>
      <PageHeader
        kicker="Authorization"
        title="AuthZEN decisions"
        description="OpenID AuthZEN 1.0 evaluations against the embedded Cedar PDP. Read-only history; mutation flows are a planned follow-up."
      />

      {events.data && decisions.length === 0 && (
        <EmptyState
          title="No decisions evaluated yet."
          hint="Send a POST to /access/v1/evaluation with subject / action / resource."
          command={`curl -sS -X POST http://127.0.0.1:8080/access/v1/evaluation \\
  -H 'Content-Type: application/json' \\
  -d '{"subject":{"type":"Spiffe","id":"spiffe://omega.local/example/web"},
       "action":{"name":"GET"},
       "resource":{"type":"HttpPath","id":"/api/foo"}}'`}
        />
      )}
      {decisions.length > 0 && (
        <ol className="overflow-hidden rounded-[6px] border border-[var(--color-line)]">
          {[...decisions].reverse().map((ev) => (
            <li
              key={ev.seq}
              className="grid grid-cols-[3rem_1fr_5rem] items-center gap-3 border-[var(--color-line)] border-b px-3 py-2.5 text-[13px] last:border-0 hover:bg-[var(--color-bg-raised)]/60"
            >
              <span className="font-mono text-[11px] text-[var(--color-fg-subtle)]">#{ev.seq}</span>
              <Mono className="truncate">{ev.subject || "—"}</Mono>
              <span className="text-right">
                {ev.decision === "allow" ? (
                  <StatusPill tone="ok">allow</StatusPill>
                ) : (
                  <StatusPill tone="warn">deny</StatusPill>
                )}
              </span>
            </li>
          ))}
        </ol>
      )}
    </>
  );
}
