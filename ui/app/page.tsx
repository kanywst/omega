"use client";

import { useQuery } from "@tanstack/react-query";
import Link from "next/link";
import { CodeBlock, Mono } from "@/components/data/code";
import { StatusPill } from "@/components/data/status-pill";
import { PageHeader } from "@/components/shell/page-header";
import { omega } from "@/lib/omega";

export default function Overview() {
  const domains = useQuery({ queryKey: ["domains"], queryFn: omega.listDomains });
  const audit = useQuery({ queryKey: ["audit", 200], queryFn: () => omega.listAudit(200) });
  const verify = useQuery({ queryKey: ["audit-verify"], queryFn: omega.verifyAudit });

  const issued = audit.data?.filter((e) => e.kind.startsWith("svid.issue")).length ?? 0;
  const decisions = audit.data?.filter((e) => e.kind === "access.evaluate").length ?? 0;
  const denies =
    audit.data?.filter((e) => e.kind === "access.evaluate" && e.decision === "deny").length ?? 0;

  return (
    <>
      <PageHeader
        kicker="Control plane"
        title="Overview"
        description="A read-only snapshot of what the Omega control plane has done since boot."
      />

      <div className="mb-10 grid grid-cols-2 gap-px overflow-hidden rounded-[6px] border border-[var(--color-line)] bg-[var(--color-line)] md:grid-cols-4">
        <Stat label="Domains" value={domains.data?.length ?? "—"} />
        <Stat label="SVIDs issued" value={issued} sub="last 200 events" />
        <Stat
          label="Decisions"
          value={decisions}
          sub={denies ? `${denies} denied` : "all permitted"}
        />
        <Stat
          label="Audit chain"
          value={
            verify.data === undefined ? (
              "—"
            ) : verify.data.valid ? (
              <StatusPill tone="ok">valid</StatusPill>
            ) : (
              <StatusPill tone="err">break @ {verify.data.first_bad_seq}</StatusPill>
            )
          }
        />
      </div>

      <section className="mb-10">
        <h2 className="mb-3 font-medium text-[14px] text-[var(--color-fg)]">Recent activity</h2>
        {audit.isLoading && <p className="text-[13px] text-[var(--color-fg-muted)]">Loading…</p>}
        {audit.data && audit.data.length === 0 && (
          <p className="text-[13px] text-[var(--color-fg-muted)]">
            No audit events yet — issue an SVID or evaluate a policy to populate this view.
          </p>
        )}
        {audit.data && audit.data.length > 0 && (
          <ol className="space-y-1.5">
            {audit.data
              .slice(-8)
              .reverse()
              .map((ev) => (
                <li
                  key={ev.seq}
                  className="flex items-center gap-3 border-[var(--color-line)] border-b py-2 text-[13px] last:border-0"
                >
                  <span className="w-12 shrink-0 font-mono text-[11px] text-[var(--color-fg-subtle)]">
                    #{ev.seq}
                  </span>
                  <span className="w-32 shrink-0 font-mono text-[12px] text-[var(--color-fg-muted)]">
                    {ev.kind}
                  </span>
                  <Mono className="flex-1 truncate">{ev.subject || "—"}</Mono>
                  <DecisionBadge decision={ev.decision} />
                </li>
              ))}
          </ol>
        )}
        <Link
          href="/audit"
          className="mt-3 inline-flex text-[12px] text-[var(--color-fg-muted)] underline-offset-2 hover:text-[var(--color-fg)] hover:underline"
        >
          See full audit chain →
        </Link>
      </section>

      <section>
        <h2 className="mb-3 font-medium text-[14px] text-[var(--color-fg)]">Try it</h2>
        <p className="mb-3 text-[13px] text-[var(--color-fg-muted)]">
          Evaluate a Cedar-backed AuthZEN decision against the running control plane.
        </p>
        <CodeBlock
          value={`curl -sS -X POST http://127.0.0.1:8080/access/v1/evaluation \\
  -H 'Content-Type: application/json' \\
  -d '{"subject":{"type":"Spiffe","id":"spiffe://omega.local/example/web"},
       "action":{"name":"GET"},
       "resource":{"type":"HttpPath","id":"/api/foo"}}'`}
        />
      </section>
    </>
  );
}

function Stat({ label, value, sub }: { label: string; value: React.ReactNode; sub?: string }) {
  return (
    <div className="flex flex-col gap-1.5 bg-[var(--color-bg)] px-4 py-3.5">
      <span className="font-mono text-[10.5px] text-[var(--color-fg-subtle)] uppercase tracking-[0.06em]">
        {label}
      </span>
      <span className="font-medium text-[20px] text-[var(--color-fg)] leading-none tracking-tight">
        {value}
      </span>
      {sub && <span className="text-[11.5px] text-[var(--color-fg-subtle)]">{sub}</span>}
    </div>
  );
}

function DecisionBadge({ decision }: { decision: string }) {
  if (decision === "ok" || decision === "allow")
    return <StatusPill tone="ok">{decision}</StatusPill>;
  if (decision === "deny") return <StatusPill tone="warn">deny</StatusPill>;
  return <StatusPill tone="neutral">{decision || "—"}</StatusPill>;
}
