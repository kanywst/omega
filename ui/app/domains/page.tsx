"use client";

import { useQuery } from "@tanstack/react-query";
import { Mono } from "@/components/data/code";
import { EmptyState } from "@/components/data/empty-state";
import { PageHeader } from "@/components/shell/page-header";
import { omega } from "@/lib/omega";

export default function DomainsPage() {
  const q = useQuery({ queryKey: ["domains"], queryFn: omega.listDomains });

  return (
    <>
      <PageHeader
        kicker="Identity"
        title="Domains"
        description="SPIFFE namespaces under spiffe://omega.local. Domains group SVIDs and apply policy."
      />

      {q.isLoading && <p className="text-[13px] text-[var(--color-fg-muted)]">Loading…</p>}
      {q.error && (
        <EmptyState
          title="Cannot reach the control plane."
          hint="Start it with the command below, or set OMEGA_API in ui/.env.local."
          command="omega server --data-dir .omega"
        />
      )}
      {q.data && q.data.length === 0 && (
        <EmptyState
          title="No domains yet."
          hint="Create one to start issuing SVIDs."
          command={`curl -sS -X POST http://127.0.0.1:8080/v1/domains \\
  -H 'Content-Type: application/json' \\
  -d '{"name":"prod","description":"production trust scope"}'`}
        />
      )}
      {q.data && q.data.length > 0 && (
        <div className="overflow-hidden rounded-[6px] border border-[var(--color-line)]">
          <table className="w-full text-[13px]">
            <thead>
              <tr className="border-[var(--color-line)] border-b bg-[var(--color-bg-raised)] text-left">
                <Th>Name</Th>
                <Th>Description</Th>
                <Th className="text-right">Created</Th>
              </tr>
            </thead>
            <tbody>
              {q.data.map((d) => (
                <tr
                  key={d.name}
                  className="border-[var(--color-line)] border-b transition-colors last:border-0 hover:bg-[var(--color-bg-raised)]/60"
                >
                  <td className="px-3 py-2.5">
                    <Mono>{d.name}</Mono>
                  </td>
                  <td className="px-3 py-2.5 text-[var(--color-fg-muted)]">
                    {d.description || <span className="text-[var(--color-fg-subtle)]">—</span>}
                  </td>
                  <td className="px-3 py-2.5 text-right font-mono text-[11.5px] text-[var(--color-fg-subtle)]">
                    {d.created_at ? new Date(d.created_at).toISOString().slice(0, 19) : "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}

function Th({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <th
      className={`px-3 py-2 font-mono text-[10.5px] text-[var(--color-fg-subtle)] uppercase tracking-[0.06em] ${className ?? ""}`}
    >
      {children}
    </th>
  );
}
