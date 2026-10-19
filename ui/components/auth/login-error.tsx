"use client";

import { X } from "lucide-react";
import { useEffect, useState } from "react";

/**
 * LoginError shows why a sign-in failed. The callback lands back on the
 * page with ?login_error=...; the message is shown once and the
 * parameter dropped from the address.
 */
export function LoginError() {
  const [message, setMessage] = useState("");

  useEffect(() => {
    const url = new URL(window.location.href);
    const err = url.searchParams.get("login_error");
    if (!err) return;
    setMessage(err);
    url.searchParams.delete("login_error");
    window.history.replaceState(window.history.state, "", url);
  }, []);

  if (!message) return null;
  return (
    <div
      role="alert"
      className="flex items-center gap-3 border-[color-mix(in_oklch,var(--color-err)_40%,var(--color-line))] border-b bg-[var(--color-bg-raised)] px-4 py-2 text-[13px]"
    >
      <span className="font-mono text-[11px] text-[var(--color-err)]">sign-in failed</span>
      <span className="min-w-0 flex-1 text-[var(--color-fg-muted)]">{message}</span>
      <button
        type="button"
        onClick={() => setMessage("")}
        aria-label="Dismiss"
        className="grid h-6 w-6 place-items-center rounded text-[var(--color-fg-subtle)] hover:text-[var(--color-fg)]"
      >
        <X size={12} />
      </button>
    </div>
  );
}
