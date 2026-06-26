"use client";

import { useQuery } from "@tanstack/react-query";
import { Mono } from "@/components/data/code";
import { EmptyState } from "@/components/data/empty-state";
import { StatusPill } from "@/components/data/status-pill";
import { PageHeader } from "@/components/shell/page-header";
import { omega } from "@/lib/omega";

export default function AuditPage() {
  const events = useQuery({ queryKey: ["audit", 500], queryFn: () => omega.listAudit(500) });
  const verify = useQuery({ queryKey: ["audit-verify"], queryFn: omega.verifyAudit });

  const action =
    verify.data === undefined ? null : verify.data.valid ? (
      <StatusPill tone="ok">chain valid</StatusPill>
    ) : (
      <StatusPill tone="err">break @ seq {verify.data.first_bad_seq}</StatusPill>
    );

  return (
    <>
      <PageHeader
        kicker="Audit"
        title="Tamper-evident chain"
        description="Every issuance and decision lands here. Each row hashes the previous; verify recomputes."
        action={action}
      />

      {events.error && (
        <EmptyState
          title="Cannot reach the audit log."
          hint="The control plane must be running and storage initialized."
          command="omega server --data-dir .omega"
        />
      )}
      {events.data && events.data.length === 0 && (
        <EmptyState
          title="No events yet."
          hint="Issue an SVID or evaluate a policy to write the first row."
          command="curl -sS http://127.0.0.1:8080/v1/bundle"
        />
      )}
      {events.data && events.data.length > 0 && (
        <ol className="overflow-hidden rounded-[6px] border border-[var(--color-line)]">
          {[...events.data].reverse().map((ev) => (
            <li
              key={ev.seq}
              className="grid grid-cols-[3rem_8.5rem_8rem_1fr_5rem] items-center gap-3 border-[var(--color-line)] border-b px-3 py-2.5 text-[13px] last:border-0 hover:bg-[var(--color-bg-raised)]/60"
            >
              <span className="font-mono text-[11px] text-[var(--color-fg-subtle)]">#{ev.seq}</span>
              <span className="font-mono text-[11px] text-[var(--color-fg-muted)]">
                {ev.ts.replace("T", " ").slice(0, 19)}
              </span>
              <span className="font-mono text-[11.5px] text-[var(--color-fg)]">{ev.kind}</span>
              <Mono className="truncate text-[var(--color-fg-muted)]">{ev.subject || "—"}</Mono>
              <span className="text-right">
                <DecisionBadge decision={ev.decision} />
              </span>
            </li>
          ))}
        </ol>
      )}
    </>
  );
}

function DecisionBadge({ decision }: { decision: string }) {
  if (decision === "ok" || decision === "allow")
    return <StatusPill tone="ok">{decision}</StatusPill>;
  if (decision === "deny") return <StatusPill tone="warn">deny</StatusPill>;
  return <StatusPill tone="neutral">{decision || "—"}</StatusPill>;
}
