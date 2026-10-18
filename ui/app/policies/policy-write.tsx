"use client";

import { usePathname } from "next/navigation";
import { Mono } from "@/components/data/code";
import { cn } from "@/lib/cn";
import { auth, OmegaError } from "@/lib/omega";
import { useSession } from "@/lib/session";

/**
 * WriteAccess says whether this page can change policy and why: writes
 * need sign-in configured on this UI and a signed-in person, and the
 * control plane still lets only a --domain-root-admin make them.
 */
export function WriteAccess() {
  const { session } = useSession();
  const pathname = usePathname();
  if (!session) return null;

  let body: React.ReactNode;
  if (session.error) {
    body = <>Read-only: this UI's sign-in is misconfigured ({session.error}).</>;
  } else if (!session.configured) {
    body = (
      <>
        Read-only: this UI has no sign-in configured, so it never changes policy. Set the{" "}
        <Mono>OMEGA_UI_OIDC_*</Mono> variables (see <Mono>ui/README.md</Mono>) to enable writes, or
        use <Mono>omega policy apply</Mono> and <Mono>omega policy delete</Mono>.
      </>
    );
  } else if (!session.user) {
    body = (
      <>
        {session.expired ? "Your session has ended. " : ""}
        <a
          href={auth.loginUrl(pathname)}
          className="text-[var(--color-fg)] underline underline-offset-2"
        >
          Sign in
        </a>{" "}
        to create, edit and delete stored policies. Only a <Mono>--domain-root-admin</Mono> may.
      </>
    );
  } else {
    body = (
      <>
        Signed in as <Mono>{session.user.spiffe_id}</Mono>. Changes are authorized and audited as
        you, through this UI.
      </>
    );
  }
  return <p className="mb-6 text-[13px] text-[var(--color-fg-muted)]">{body}</p>;
}

export function CedarTextarea({
  value,
  onChange,
  onSubmit,
  rows = 8,
  label = "Cedar policy text",
  autoFocus,
}: {
  value: string;
  onChange: (v: string) => void;
  onSubmit?: () => void;
  rows?: number;
  label?: string;
  autoFocus?: boolean;
}) {
  return (
    <textarea
      value={value}
      onChange={(e) => onChange(e.target.value)}
      onKeyDown={(e) => {
        if (onSubmit && e.key === "Enter" && (e.metaKey || e.ctrlKey)) {
          e.preventDefault();
          onSubmit();
        }
      }}
      spellCheck={false}
      rows={rows}
      aria-label={label}
      // biome-ignore lint/a11y/noAutofocus: the editor opens on an explicit Edit click.
      autoFocus={autoFocus}
      placeholder={`forbid (
  principal == Spiffe::"spiffe://omega.local/media/web",
  action == Action::"read",
  resource
);`}
      className="block w-full resize-y rounded-[6px] border border-[var(--color-line)] bg-[var(--color-bg-raised)] p-3 font-mono text-[12.5px] text-[var(--color-fg)] leading-relaxed outline-none placeholder:text-[var(--color-fg-subtle)] focus:border-[var(--color-line-strong)]"
    />
  );
}

/** ErrorPanel shows a failed request's message in the page's error frame. */
export function ErrorPanel({
  children,
  className,
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div
      role="alert"
      className={cn(
        "mt-3 rounded-[6px] border border-[color-mix(in_oklch,var(--color-err)_40%,var(--color-line))] p-3 text-[13px] text-[var(--color-fg)] leading-relaxed",
        className,
      )}
    >
      {children}
    </div>
  );
}

/** writeMessage explains a failed create, update or delete. */
export function writeMessage(err: Error): string {
  if (!(err instanceof OmegaError)) return err.message;
  const detail = err.detail;
  switch (err.status) {
    case 400:
      return detail || "The policy does not parse.";
    case 401:
      return detail || "Your session has ended. Sign in again.";
    case 403:
      return detail.includes("--domain-root-admin")
        ? `${detail}. Only a --domain-root-admin may change stored policies.`
        : detail || "The control plane refused the change.";
    case 404:
      return detail || "The policy no longer exists.";
    case 409:
      return detail || "A policy with this id already exists.";
    case 412:
      return "This policy changed since you opened it, so nothing was saved. Load the current version and make your change again.";
    case 503:
      return (
        detail ||
        "The control plane cannot take writes right now (not the leader, or misconfigured)."
      );
    default:
      return detail || err.message;
  }
}
