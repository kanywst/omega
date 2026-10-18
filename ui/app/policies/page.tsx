"use client";

import { useMutation, useQuery } from "@tanstack/react-query";
import Link from "next/link";
import { useState } from "react";
import { Mono } from "@/components/data/code";
import { EmptyState } from "@/components/data/empty-state";
import { StatusPill } from "@/components/data/status-pill";
import { PageHeader } from "@/components/shell/page-header";
import { Button } from "@/components/ui/button";
import { Kbd } from "@/components/ui/kbd";
import { OmegaError, omega, type Policy } from "@/lib/omega";
import { PolicyError, retryPolicyRead } from "./policy-error";

export default function PoliciesPage() {
  const q = useQuery({
    queryKey: ["policies"],
    queryFn: omega.listPolicies,
    retry: retryPolicyRead,
  });

  return (
    <>
      <PageHeader
        kicker="Authorization"
        title="Policies"
        description="The Cedar policies the engine evaluates: --policy-dir files and policies stored through the API."
        action={<StatusPill tone="neutral">read-only</StatusPill>}
      />

      <p className="mb-6 text-[13px] text-[var(--color-fg-muted)]">
        This UI's proxy does not authenticate, so it never changes policy. Use{" "}
        <Mono>omega policy apply</Mono> and <Mono>omega policy delete</Mono>.
      </p>

      {q.isLoading && <p className="text-[13px] text-[var(--color-fg-muted)]">Loading…</p>}
      {q.error && <PolicyError error={q.error} />}
      {q.data && q.data.length === 0 && (
        <EmptyState
          title="No policies yet."
          hint="Add *.cedar files to --policy-dir, or store one through the API."
          command={`omega policy apply -f block-media-web.cedar \\
  --server https://omega:8080 --server-ca ca.pem \\
  --client-cert root.pem --client-key root.key`}
        />
      )}
      {q.data && q.data.length > 0 && (
        <ol className="overflow-hidden rounded-[6px] border border-[var(--color-line)]">
          {/* File ids are *.cedar names and stored ids cannot hold a ".",
              so an id names one policy and /policies/<id> is unambiguous. */}
          {q.data.map((p) => (
            <PolicyRow key={p.id} policy={p} />
          ))}
        </ol>
      )}

      <ValidatePanel />
    </>
  );
}

function PolicyRow({ policy: p }: { policy: Policy }) {
  return (
    <li className="border-[var(--color-line)] border-b last:border-0">
      <Link
        href={`/policies/${encodeURIComponent(p.id)}`}
        className="grid grid-cols-[1fr_auto] items-center gap-x-3 gap-y-1 px-3 py-2.5 text-[13px] transition-colors hover:bg-[var(--color-bg-raised)]/60"
      >
        <span className="flex min-w-0 items-center gap-2.5">
          <Mono>{p.id}</Mono>
          <StatusPill tone={p.source === "api" ? "ok" : "neutral"}>{p.source}</StatusPill>
          {p.version !== undefined && (
            <span className="font-mono text-[11px] text-[var(--color-fg-subtle)]">
              v{p.version}
            </span>
          )}
        </span>
        <span className="text-right font-mono text-[11px] text-[var(--color-fg-muted)]">
          {p.updated_at ? p.updated_at.replace("T", " ").slice(0, 19) : ""}
        </span>
        <Mono className="break-all text-[11px] text-[var(--color-fg-subtle)]">{p.digest}</Mono>
        <Mono className="text-right text-[11px] text-[var(--color-fg-subtle)]">
          {p.updated_by ?? ""}
        </Mono>
      </Link>
    </li>
  );
}

function ValidatePanel() {
  const [text, setText] = useState("");
  const m = useMutation({ mutationFn: omega.validatePolicy });
  const submit = () => text.trim() && !m.isPending && m.mutate(text);
  const invalid = m.error instanceof OmegaError && m.error.status === 400 ? m.error : null;

  return (
    <section className="mt-10">
      <h2 className="mb-1 font-medium text-[14px] text-[var(--color-fg)]">Validate</h2>
      <p className="mb-3 text-[13px] text-[var(--color-fg-muted)]">
        Runs the checks a create runs and stores nothing.
      </p>
      <textarea
        value={text}
        onChange={(e) => setText(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) {
            e.preventDefault();
            submit();
          }
        }}
        spellCheck={false}
        rows={8}
        aria-label="Cedar policy text"
        placeholder={`forbid (
  principal == Spiffe::"spiffe://omega.local/media/web",
  action == Action::"read",
  resource
);`}
        className="block w-full resize-y rounded-[6px] border border-[var(--color-line)] bg-[var(--color-bg-raised)] p-3 font-mono text-[12.5px] text-[var(--color-fg)] leading-relaxed outline-none placeholder:text-[var(--color-fg-subtle)] focus:border-[var(--color-line-strong)]"
      />
      <div className="mt-3 flex items-center gap-3">
        <Button size="sm" variant="outline" onClick={submit} disabled={!text.trim() || m.isPending}>
          Validate
        </Button>
        <Kbd>⌘↵</Kbd>
        <span className="ml-auto">
          {m.isPending && <StatusPill tone="neutral">checking</StatusPill>}
          {m.data && <StatusPill tone="ok">valid</StatusPill>}
          {invalid && <StatusPill tone="err">invalid</StatusPill>}
          {m.error && !invalid && (
            <StatusPill tone="warn">
              {m.error instanceof OmegaError ? m.error.status : "unreachable"}
            </StatusPill>
          )}
        </span>
      </div>
      {m.data && (
        <div className="mt-3 rounded-[6px] border border-[var(--color-line)] px-3 py-2.5">
          <p className="mb-1.5 font-mono text-[10.5px] text-[var(--color-fg-subtle)] uppercase tracking-[0.06em]">
            Policy ids once stored
          </p>
          <ul className="space-y-0.5">
            {m.data.policy_ids.map((id) => (
              <li key={id}>
                <Mono>{id}</Mono>
              </li>
            ))}
          </ul>
        </div>
      )}
      {m.error && (
        <pre className="mt-3 overflow-x-auto whitespace-pre-wrap rounded-[6px] border border-[color-mix(in_oklch,var(--color-err)_40%,var(--color-line))] p-3 font-mono text-[12.5px] text-[var(--color-fg)] leading-relaxed">
          {validateMessage(m.error)}
        </pre>
      )}
    </section>
  );
}

function validateMessage(err: Error): string {
  if (!(err instanceof OmegaError)) return err.message;
  switch (err.status) {
    case 400:
      return err.detail || "The policy does not parse.";
    case 401:
    case 403:
      return `${err.detail || `HTTP ${err.status}`}\nThe control plane runs with --require-auth and this UI's proxy presents no SVID.`;
    default:
      return err.detail || err.message;
  }
}
