"use client";

import { useQuery } from "@tanstack/react-query";
import { auth, setCSRFToken } from "@/lib/omega";

/**
 * useSession is who is signed in to this UI, if anyone. canWrite is
 * true only for a live session: the policy pages then offer create,
 * edit and delete, which the control plane still authorizes as that
 * person.
 */
export function useSession() {
  const q = useQuery({
    queryKey: ["session"],
    queryFn: async () => {
      const s = await auth.session();
      setCSRFToken(s.csrf ?? "");
      return s;
    },
    staleTime: 30_000,
    refetchInterval: 60_000,
    retry: false,
  });
  return { ...q, session: q.data, canWrite: !!q.data?.user };
}
