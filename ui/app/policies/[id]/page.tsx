"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { useState } from "react";
import { CodeBlock, Mono } from "@/components/data/code";
import { StatusPill } from "@/components/data/status-pill";
import { PageHeader } from "@/components/shell/page-header";
import { Button } from "@/components/ui/button";
import { Kbd } from "@/components/ui/kbd";
import { OmegaError, omega, type Policy } from "@/lib/omega";
import { useSession } from "@/lib/session";
import { PolicyError, retryPolicyRead } from "../policy-error";
import { CedarTextarea, ErrorPanel, WriteAccess, writeMessage } from "../policy-write";

export default function PolicyDetailPage() {
  const params = useParams<{ id: string }>();
  const id = decode(params.id);
  const q = useQuery({
    queryKey: ["policy", id],
    queryFn: () => omega.getPolicy(id),
    retry: retryPolicyRead,
  });
  const { canWrite } = useSession();
  const [mode, setMode] = useState<"view" | "edit" | "delete">("view");
  const writable = canWrite && q.data?.source === "api";

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
            <div className="flex items-center gap-2">
              <StatusPill tone={q.data.source === "api" ? "ok" : "neutral"}>
                {q.data.source}
              </StatusPill>
              {writable && mode === "view" && (
                <>
                  <Button size="sm" variant="outline" onClick={() => setMode("edit")}>
                    Edit
                  </Button>
                  <Button size="sm" variant="danger" onClick={() => setMode("delete")}>
                    Delete
                  </Button>
                </>
              )}
            </div>
          )
        }
      />
      {q.data?.source === "api" && <WriteAccess />}

      {q.isLoading && <p className="text-[13px] text-[var(--color-fg-muted)]">Loading…</p>}
      {q.error && <PolicyError error={q.error} id={id} />}
      {q.data && (
        <div className="space-y-8">
          {writable && mode === "delete" && (
            <DeletePanel policy={q.data} onCancel={() => setMode("view")} />
          )}
          <Metadata policy={q.data} />
          {writable && mode === "edit" ? (
            <EditPanel policy={q.data} onDone={() => setMode("view")} />
          ) : (
            <section>
              <h2 className="mb-3 font-medium text-[14px] text-[var(--color-fg)]">Cedar</h2>
              <CodeBlock value={q.data.text ?? ""} />
            </section>
          )}
        </div>
      )}
    </>
  );
}

const isConflict = (err: Error | null) => err instanceof OmegaError && err.status === 412;

// EditPanel replaces the policy's text, sending the ETag it was read
// with. A 412 keeps the draft and offers to load the current version.
function EditPanel({ policy, onDone }: { policy: Policy; onDone: () => void }) {
  const [text, setText] = useState(policy.text ?? "");
  const qc = useQueryClient();
  const m = useMutation({
    mutationFn: () => omega.updatePolicy(policy.id, text, policy.etag ?? ""),
    onSuccess: async (p) => {
      qc.setQueryData(["policy", policy.id], p);
      await qc.invalidateQueries({ queryKey: ["policies"] });
      onDone();
    },
  });
  const reload = async () => {
    m.reset();
    const fresh = await qc.fetchQuery({
      queryKey: ["policy", policy.id],
      queryFn: () => omega.getPolicy(policy.id),
      staleTime: 0,
    });
    setText(fresh.text ?? "");
  };
  const changed = text !== (policy.text ?? "");
  const submit = () => changed && text.trim() && !m.isPending && m.mutate();

  return (
    <section>
      <div className="mb-3 flex items-baseline gap-3">
        <h2 className="font-medium text-[14px] text-[var(--color-fg)]">Cedar</h2>
        <span className="font-mono text-[11px] text-[var(--color-fg-subtle)]">
          editing v{policy.version}, If-Match {policy.etag}
        </span>
      </div>
      <CedarTextarea
        value={text}
        onChange={setText}
        onSubmit={submit}
        rows={Math.max(8, text.split("\n").length + 1)}
        autoFocus
      />
      <div className="mt-3 flex items-center gap-3">
        <Button size="sm" onClick={submit} disabled={!changed || !text.trim() || m.isPending}>
          Save
        </Button>
        <Button size="sm" variant="ghost" onClick={onDone} disabled={m.isPending}>
          Cancel
        </Button>
        <Kbd>⌘↵</Kbd>
        {m.isPending && (
          <span className="ml-auto">
            <StatusPill tone="neutral">saving</StatusPill>
          </span>
        )}
        {isConflict(m.error) && (
          <span className="ml-auto">
            <StatusPill tone="warn">412 conflict</StatusPill>
          </span>
        )}
      </div>
      {m.error && (
        <ErrorPanel>
          <p>{writeMessage(m.error)}</p>
          {isConflict(m.error) && (
            <div className="mt-3 flex items-center gap-3">
              <Button size="sm" variant="outline" onClick={reload}>
                Load the current version
              </Button>
              <span className="text-[12px] text-[var(--color-fg-subtle)]">
                Replaces your draft with what is stored now.
              </span>
            </div>
          )}
        </ErrorPanel>
      )}
    </section>
  );
}

// DeletePanel asks for the policy id to be typed before deleting, and
// deletes only the version the page read (If-Match).
function DeletePanel({ policy, onCancel }: { policy: Policy; onCancel: () => void }) {
  const [typed, setTyped] = useState("");
  const router = useRouter();
  const qc = useQueryClient();
  const m = useMutation({
    mutationFn: () => omega.deletePolicy(policy.id, policy.etag ?? ""),
    onSuccess: async () => {
      qc.removeQueries({ queryKey: ["policy", policy.id] });
      await qc.invalidateQueries({ queryKey: ["policies"] });
      router.push("/policies");
    },
  });
  const confirmed = typed === policy.id;

  return (
    <section
      aria-label="Delete policy"
      className="rounded-[6px] border border-[color-mix(in_oklch,var(--color-err)_40%,var(--color-line))] p-4"
    >
      <h2 className="font-medium text-[14px] text-[var(--color-fg)]">Delete this policy?</h2>
      <p className="mt-1 text-[13px] text-[var(--color-fg-muted)]">
        Every replica and node agent stops evaluating it. The deletion is audited as you. Type{" "}
        <Mono>{policy.id}</Mono> to confirm.
      </p>
      <input
        value={typed}
        onChange={(e) => setTyped(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === "Enter" && confirmed && !m.isPending) m.mutate();
        }}
        spellCheck={false}
        autoComplete="off"
        aria-label="Policy id to confirm"
        // biome-ignore lint/a11y/noAutofocus: the panel opens on an explicit Delete click.
        autoFocus
        className="mt-3 block h-8 w-full max-w-sm rounded-[6px] border border-[var(--color-line)] bg-[var(--color-bg-raised)] px-2.5 font-mono text-[12.5px] text-[var(--color-fg)] outline-none focus:border-[var(--color-line-strong)]"
      />
      <div className="mt-3 flex items-center gap-3">
        <Button
          size="sm"
          variant="danger"
          onClick={() => m.mutate()}
          disabled={!confirmed || m.isPending}
        >
          Delete v{policy.version}
        </Button>
        <Button size="sm" variant="ghost" onClick={onCancel} disabled={m.isPending}>
          Cancel
        </Button>
      </div>
      {m.error && (
        <ErrorPanel>
          <p>{writeMessage(m.error)}</p>
          {isConflict(m.error) && (
            <div className="mt-3">
              <Button
                size="sm"
                variant="outline"
                onClick={() => {
                  m.reset();
                  setTyped("");
                  qc.invalidateQueries({ queryKey: ["policy", policy.id] });
                }}
              >
                Load the current version
              </Button>
            </div>
          )}
        </ErrorPanel>
      )}
    </section>
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
