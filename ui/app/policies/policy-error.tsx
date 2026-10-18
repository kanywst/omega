import { EmptyState } from "@/components/data/empty-state";
import { OmegaError } from "@/lib/omega";

const cli = (args: string) => `omega policy ${args} \\
  --server https://omega:8080 --server-ca ca.pem \\
  --client-cert root.pem --client-key root.key`;

// retryPolicyRead retries once, but not a 4xx: a refused or missing
// policy will not change on a second try.
export function retryPolicyRead(failures: number, error: Error) {
  if (error instanceof OmegaError && error.status >= 400 && error.status < 500) return false;
  return failures < 1;
}

// PolicyError maps a failed policy read to an empty state. Under
// --require-auth the UI's proxy needs its own client certificate, and
// the text of a policy needs a signed-in --domain-root-admin; otherwise
// the CLI is the way in.
export function PolicyError({ error, id }: { error: Error; id?: string }) {
  // 0: the request never got an answer; -1: an answer this UI cannot read.
  const status = error instanceof OmegaError ? error.status : error instanceof TypeError ? 0 : -1;
  const detail = error instanceof OmegaError ? error.detail : "";

  switch (status) {
    case 401:
      return (
        <EmptyState
          title="The control plane did not accept this request."
          hint={
            detail ||
            "It runs with --require-auth: give this UI an SVID with OMEGA_API_CLIENT_CERT and OMEGA_API_CLIENT_KEY, or read policies with the CLI."
          }
          command={cli(id ? `get ${id}` : "list")}
        />
      );
    case 403:
      return (
        <EmptyState
          title={id ? "Not allowed to read this policy's text." : "Not allowed to list policies."}
          hint={
            id
              ? "Under --require-auth the text is served to a --domain-root-admin or a --decision-recorder only. Sign in as a root admin, or use the CLI."
              : detail || "The control plane refused the request."
          }
          command={cli(id ? `get ${id}` : "list")}
        />
      );
    case 404:
      return (
        <EmptyState
          title={`No policy named ${id ?? "this"}.`}
          hint="It is neither a stored policy nor a --policy-dir file. List what exists:"
          command={cli("list")}
        />
      );
    case 503:
      return (
        <EmptyState
          title="The control plane is not serving policies right now."
          hint={`${detail ? `${detail}. ` : ""}When the stored policy set fails to load, the server logs the error and counts it in omega_stored_policy_set_load_failures_total.`}
          command="curl -sS http://127.0.0.1:8080/metrics | grep omega_stored_polic"
        />
      );
    case 0:
    case 502:
      return (
        <EmptyState
          title="Cannot reach the control plane."
          hint="Start it with the command below, or set OMEGA_API in ui/.env.local."
          command="omega server --data-dir .omega"
        />
      );
    case -1:
      return (
        <EmptyState title="Unexpected response from the control plane." hint={error.message} />
      );
    default:
      return (
        <EmptyState title={`The control plane answered ${status}.`} hint={detail || undefined} />
      );
  }
}
