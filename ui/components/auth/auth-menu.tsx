"use client";

import { useQueryClient } from "@tanstack/react-query";
import { usePathname } from "next/navigation";
import { useState } from "react";
import { StatusPill } from "@/components/data/status-pill";
import { Button } from "@/components/ui/button";
import { auth } from "@/lib/omega";
import { useSession } from "@/lib/session";

/**
 * AuthMenu is the topbar's sign-in state: nothing when sign-in is not
 * configured, a Sign in link when nobody is signed in, and the signed-in
 * person's SPIFFE ID with Sign out otherwise.
 */
export function AuthMenu() {
  const { session } = useSession();
  const pathname = usePathname();
  const qc = useQueryClient();
  const [leaving, setLeaving] = useState(false);

  if (!session) return null;
  if (session.error) {
    return (
      <span title={session.error}>
        <StatusPill tone="warn">sign-in misconfigured</StatusPill>
      </span>
    );
  }
  if (!session.configured) return null;

  if (!session.user) {
    return (
      <Button asChild size="sm" variant="outline">
        <a href={auth.loginUrl(pathname)}>Sign in</a>
      </Button>
    );
  }

  const signOut = async () => {
    setLeaving(true);
    try {
      await auth.logout();
    } finally {
      setLeaving(false);
      await qc.invalidateQueries();
    }
  };
  return (
    <div className="flex items-center gap-2">
      <span className="text-right leading-tight">
        <span className="block text-[12px] text-[var(--color-fg)]">{session.user.name}</span>
        <span className="block font-mono text-[10.5px] text-[var(--color-fg-subtle)]">
          {session.user.spiffe_id}
        </span>
      </span>
      <Button size="sm" variant="ghost" onClick={signOut} disabled={leaving}>
        Sign out
      </Button>
    </div>
  );
}
