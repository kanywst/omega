"use client";

import { useQuery } from "@tanstack/react-query";
import Link from "next/link";
import { useParams } from "next/navigation";
import { CodeBlock, Mono } from "@/components/data/code";
import { StatusPill } from "@/components/data/status-pill";
import { PageHeader } from "@/components/shell/page-header";
import { omega, type Policy } from "@/lib/omega";
import { PolicyError, retryPolicyRead } from "../policy-error";

export default function PolicyDetailPage() {
  const params = useParams<{ id: string }>();
  const id = decode(params.id);
  const q = useQuery({
    queryKey: ["policy", id],
    queryFn: () => omega.getPolicy(id),
    retry: retryPolicyRead,
  });

  return (
    <>
      <Link
        href="/policies"
        className="mb-4 inline-flex text-[12px] text-[var(--color-fg-muted)] underline-offset-2 hover:text-[var(--color-fg)] hover:underline"
      >
        ← Policies
      </Link>
      <PageHeader
        kicker="Policy"
        title={id}
        description={
          q.data?.source === "file"
            ? "A --policy-dir file. Read-only over the API: edit the file and send SIGHUP."
            : q.data?.source === "api"
              ? `Stored through the API. Every Cedar policy id it defines is prefixed with api/${id}::.`
              : undefined
        }
        action={
          q.data && (
            <StatusPill tone={q.data.source === "api" ? "ok" : "neutral"}>
              {q.data.source}
            </StatusPill>
          )
        }
      />

      {q.isLoading && <p className="text-[13px] text-[var(--color-fg-muted)]">Loading…</p>}
      {q.error && <PolicyError error={q.error} id={id} />}
      {q.data && (
        <div className="space-y-8">
          <Metadata policy={q.data} />
          <section>
            <h2 className="mb-3 font-medium text-[14px] text-[var(--color-fg)]">Cedar</h2>
            <CodeBlock value={q.data.text ?? ""} />
          </section>
        </div>
      )}
    </>
  );
}

function Metadata({ policy: p }: { policy: Policy }) {
  const rows: [string, string | undefined][] = [
    ["Version", p.version?.toString()],
    ["Digest", p.digest],
    ["ETag", p.etag],
    ["Created by", p.created_by],
    ["Created", p.created_at && timestamp(p.created_at)],
    ["Updated by", p.updated_by],
    ["Updated", p.updated_at && timestamp(p.updated_at)],
  ];
  return (
    <dl className="overflow-hidden rounded-[6px] border border-[var(--color-line)]">
      {rows
        .filter(([, v]) => v)
        .map(([k, v]) => (
          <div
            key={k}
            className="grid grid-cols-[8rem_1fr] items-baseline gap-3 border-[var(--color-line)] border-b px-3 py-2.5 last:border-0"
          >
            <dt className="font-mono text-[10.5px] text-[var(--color-fg-subtle)] uppercase tracking-[0.06em]">
              {k}
            </dt>
            <dd className="min-w-0 break-all">
              <Mono>{v}</Mono>
            </dd>
          </div>
        ))}
    </dl>
  );
}

function timestamp(ts: string) {
  return ts.replace("T", " ").slice(0, 19);
}

// useParams can hand back the segment still percent-encoded.
function decode(segment: string) {
  try {
    return decodeURIComponent(segment);
  } catch {
    return segment;
  }
}
