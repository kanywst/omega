/**
 * Typed client for the Omega control plane HTTP API.
 *
 * In dev, requests go to /api/omega/* which Next rewrites to OMEGA_API
 * (default http://127.0.0.1:8080). Keeps CORS out of the picture.
 */

import { z } from "zod";

const base = "/api/omega";

async function get<T>(path: string, schema: z.ZodSchema<T>): Promise<T> {
  const res = await fetch(`${base}${path}`, { cache: "no-store" });
  if (!res.ok) {
    throw new OmegaError(res.status, `GET ${path} -> ${res.status}`, await errorDetail(res));
  }
  return schema.parse(await res.json());
}

// The signed-in session's CSRF token, sent with every state-changing
// request. useSession sets it.
let csrfToken = "";
export function setCSRFToken(token: string) {
  csrfToken = token;
}

async function send(
  method: "POST" | "PUT" | "DELETE",
  path: string,
  body?: unknown,
  headers: Record<string, string> = {},
): Promise<Response> {
  const res = await fetch(`${base}${path}`, {
    method,
    headers: {
      ...(body === undefined ? {} : { "Content-Type": "application/json" }),
      ...(csrfToken ? { "X-Omega-CSRF": csrfToken } : {}),
      ...headers,
    },
    body: body === undefined ? undefined : JSON.stringify(body),
    cache: "no-store",
  });
  if (!res.ok) {
    throw new OmegaError(res.status, `${method} ${path} -> ${res.status}`, await errorDetail(res));
  }
  return res;
}

async function post<T>(path: string, body: unknown, schema: z.ZodSchema<T>): Promise<T> {
  return schema.parse(await (await send("POST", path, body)).json());
}

const ErrorBody = z.object({ error: z.string() });

// errorDetail is the server's `{"error": "..."}` message, or the plain
// text the proxy answers with when the control plane is unreachable.
async function errorDetail(res: Response): Promise<string> {
  const text = await res.text().catch(() => "");
  try {
    const parsed = ErrorBody.safeParse(JSON.parse(text));
    if (parsed.success) return parsed.data.error;
  } catch {
    // not JSON
  }
  return text.trim();
}

export class OmegaError extends Error {
  constructor(
    public status: number,
    message: string,
    public detail = "",
  ) {
    super(message);
    this.name = "OmegaError";
  }
}

export const Domain = z.object({
  name: z.string(),
  description: z.string().optional().default(""),
  created_at: z.string().optional(),
});
export type Domain = z.infer<typeof Domain>;

const DomainList = z.object({ items: z.array(Domain) });

export const AuditEvent = z.object({
  seq: z.number(),
  ts: z.string(),
  kind: z.string(),
  subject: z.string(),
  decision: z.string(),
  payload: z.unknown(),
  prev_hash: z.string().optional(),
  hash: z.string().optional(),
});
export type AuditEvent = z.infer<typeof AuditEvent>;

const AuditList = z.object({ items: z.array(AuditEvent) });

const AuditVerify = z.object({
  valid: z.boolean(),
  first_bad_seq: z.number().optional(),
});

export const Policy = z.object({
  id: z.string(),
  source: z.enum(["api", "file"]),
  text: z.string().optional(),
  digest: z.string(),
  version: z.number().optional(),
  etag: z.string().optional(),
  created_by: z.string().optional(),
  created_at: z.string().optional(),
  updated_by: z.string().optional(),
  updated_at: z.string().optional(),
});
export type Policy = z.infer<typeof Policy>;

const PolicyList = z.object({ items: z.array(Policy) });

export const PolicyValidation = z.object({
  valid: z.boolean(),
  policy_ids: z.array(z.string()),
});
export type PolicyValidation = z.infer<typeof PolicyValidation>;

export const Session = z.object({
  configured: z.boolean(),
  error: z.string().optional(),
  expired: z.boolean().optional(),
  user: z.object({ spiffe_id: z.string(), name: z.string(), expires_at: z.string() }).optional(),
  csrf: z.string().optional(),
});
export type Session = z.infer<typeof Session>;

const policyPath = (id: string) => `/v1/policies/${encodeURIComponent(id)}`;

export const auth = {
  session: async () => {
    const res = await fetch("/api/auth/session", { cache: "no-store" });
    if (!res.ok) throw new OmegaError(res.status, "session", await errorDetail(res));
    return Session.parse(await res.json());
  },
  loginUrl: (returnTo: string) => `/api/auth/login?return_to=${encodeURIComponent(returnTo)}`,
  logout: async () => {
    const res = await fetch("/api/auth/logout", {
      method: "POST",
      headers: csrfToken ? { "X-Omega-CSRF": csrfToken } : {},
      cache: "no-store",
    });
    if (!res.ok) throw new OmegaError(res.status, "logout", await errorDetail(res));
  },
};

export const omega = {
  health: () => fetch(`${base}/healthz`, { cache: "no-store" }).then((r) => r.ok),
  listDomains: () => get("/v1/domains", DomainList).then((d) => d.items),
  listAudit: (limit = 50) => get(`/v1/audit?limit=${limit}`, AuditList).then((d) => d.items),
  verifyAudit: () => get("/v1/audit/verify", AuditVerify),
  listPolicies: () => get("/v1/policies", PolicyList).then((d) => d.items),
  getPolicy: (id: string) => get(policyPath(id), Policy),
  validatePolicy: (text: string) => post("/v1/policies/validate", { text }, PolicyValidation),
  createPolicy: (id: string, text: string) => post("/v1/policies", { id, text }, Policy),
  // updatePolicy and deletePolicy send the ETag the page read, so a
  // version someone else wrote since answers 412 instead of being lost.
  updatePolicy: async (id: string, text: string, etag: string) =>
    Policy.parse(await (await send("PUT", policyPath(id), { text }, { "If-Match": etag })).json()),
  deletePolicy: async (id: string, etag: string) => {
    await send("DELETE", policyPath(id), undefined, { "If-Match": etag });
  },
  bundleUrl: () => `${base}/v1/bundle`,
  jwtBundleUrl: () => `${base}/v1/jwt/bundle`,
};
