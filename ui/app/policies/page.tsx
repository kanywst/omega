"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { Mono } from "@/components/data/code";
import { EmptyState } from "@/components/data/empty-state";
import { StatusPill } from "@/components/data/status-pill";
import { PageHeader } from "@/components/shell/page-header";
import { Button } from "@/components/ui/button";
import { Kbd } from "@/components/ui/kbd";
import { OmegaError, omega, type Policy } from "@/lib/omega";
import { useSession } from "@/lib/session";
import { PolicyError, retryPolicyRead } from "./policy-error";
import { CedarTextarea, ErrorPanel, WriteAccess, writeMessage } from "./policy-write";

export default function PoliciesPage() {
  const q = useQuery({
    queryKey: ["policies"],
    queryFn: omega.listPolicies,
    retry: retryPolicyRead,
  });
  const { canWrite } = useSession();
  const [creating, setCreating] = useState(false);

  return (
    <>
      <PageHeader
        kicker="Authorization"
        title="Policies"
        description="The Cedar policies the engine evaluates: --policy-dir files and policies stored through the API."
        action={
          canWrite ? (
            <Button size="sm" onClick={() => setCreating(true)} disabled={creating}>
              New policy
            </Button>
          ) : (
            <StatusPill tone="neutral">read-only</StatusPill>
          )
        }
      />

      <WriteAccess />
      {canWrite && creating && <CreatePanel onCancel={() => setCreating(false)} />}

      {q.isLoading && <p className="text-[13px] text-[var(--color-fg-muted)]">Loading…</p>}
      {q.error && <PolicyError error={q.error} />}
      {q.data && q.data.length === 0 && (
        <EmptyState
          title="No policies yet."
          hint={
            canWrite
              ? "Create one with New policy, or add *.cedar files to --policy-dir."
              : "Add *.cedar files to --policy-dir, or store one through the API."
          }
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

// CreatePanel stores a new policy as the signed-in person and opens it.
function CreatePanel({ onCancel }: { onCancel: () => void }) {
  const [id, setId] = useState("");
  const [text, setText] = useState("");
  const router = useRouter();
  const qc = useQueryClient();
  const m = useMutation({
    mutationFn: () => omega.createPolicy(id.trim(), text),
    onSuccess: async (p) => {
      await qc.invalidateQueries({ queryKey: ["policies"] });
      router.push(`/policies/${encodeURIComponent(p.id)}`);
    },
  });
  const ready = id.trim() !== "" && text.trim() !== "" && !m.isPending;
  const submit = () => ready && m.mutate();

  return (
    <section className="mb-8 rounded-[6px] border border-[var(--color-line)] p-4">
      <h2 className="mb-3 font-medium text-[14px] text-[var(--color-fg)]">New policy</h2>
      <label className="mb-3 block">
        <span className="mb-1.5 block font-mono text-[10.5px] text-[var(--color-fg-subtle)] uppercase tracking-[0.06em]">
          Id
        </span>
        <input
          value={id}
          onChange={(e) => setId(e.target.value)}
          spellCheck={false}
          autoComplete="off"
          placeholder="block-media-web"
          className="block h-8 w-full max-w-sm rounded-[6px] border border-[var(--color-line)] bg-[var(--color-bg-raised)] px-2.5 font-mono text-[12.5px] text-[var(--color-fg)] outline-none placeholder:text-[var(--color-fg-subtle)] focus:border-[var(--color-line-strong)]"
        />
        <span className="mt-1 block text-[12px] text-[var(--color-fg-subtle)]">
          1-63 lowercase letters, digits, - or _. Its Cedar policy ids become{" "}
          <Mono className="text-[12px] text-[var(--color-fg-subtle)]">
            api/{id.trim() || "<id>"}::…
          </Mono>
        </span>
      </label>
      <CedarTextarea value={text} onChange={setText} onSubmit={submit} />
      <div className="mt-3 flex items-center gap-3">
        <Button size="sm" onClick={submit} disabled={!ready}>
          Create
        </Button>
        <Button size="sm" variant="ghost" onClick={onCancel} disabled={m.isPending}>
          Cancel
        </Button>
        <Kbd>⌘↵</Kbd>
        {m.isPending && (
          <span className="ml-auto">
            <StatusPill tone="neutral">saving</StatusPill>
          </span>
        )}
      </div>
      {m.error && <ErrorPanel>{writeMessage(m.error)}</ErrorPanel>}
    </section>
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
      <CedarTextarea value={text} onChange={setText} onSubmit={submit} />
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
      return `${err.detail || `HTTP ${err.status}`}\nThe control plane runs with --require-auth and refused this UI's request.`;
    default:
      return err.detail || err.message;
  }
}
