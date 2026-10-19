import type { NextRequest } from "next/server";
import { authState, upstreamConfig } from "@/lib/server/config";
import {
  CSRF_HEADER,
  csrfOK,
  currentSession,
  SESSION_COOKIE,
  sameOrigin,
  USER_TOKEN_HEADER,
} from "@/lib/server/session";
import { omegaRequest } from "@/lib/server/upstream";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

const HOP_BY_HOP = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
  "host",
  "content-length",
]);

// Never forwarded to the control plane: the browser's credentials for
// this UI, and anything that could pass for the person's token.
const REQUEST_ONLY = new Set(["cookie", "authorization", USER_TOKEN_HEADER, CSRF_HEADER]);
// Never handed to the browser.
const RESPONSE_ONLY = new Set(["set-cookie"]);

const UNSAFE = new Set(["POST", "PUT", "PATCH", "DELETE"]);

// The calls the UI's pages make, and nothing else: the proxy presents
// the UI's own X.509-SVID, so forwarding any path would let anyone who
// reaches the UI call any route as the UI. "*" is one policy id. A
// signedIn route is only forwarded with a person's token. A sessionOnly
// route reads what the control plane shows only to authenticated
// callers, so while the UI presents its SVID it is only forwarded for a
// signed-in browser.
const ROUTES: { methods: string[]; path: string[]; signedIn?: true; sessionOnly?: true }[] = [
  { methods: ["GET", "HEAD"], path: ["healthz"] },
  { methods: ["GET", "HEAD"], path: ["v1", "domains"] },
  { methods: ["GET", "HEAD"], path: ["v1", "audit"], sessionOnly: true },
  { methods: ["GET", "HEAD"], path: ["v1", "audit", "verify"], sessionOnly: true },
  { methods: ["GET", "HEAD"], path: ["v1", "policies"] },
  { methods: ["POST"], path: ["v1", "policies"], signedIn: true },
  { methods: ["POST"], path: ["v1", "policies", "validate"] },
  { methods: ["GET", "HEAD"], path: ["v1", "policies", "*"] },
  { methods: ["PUT", "DELETE"], path: ["v1", "policies", "*"], signedIn: true },
];

const DOT_SEGMENTS = new Set(["", ".", ".."]);

const route = (method: string, path: string[]) =>
  ROUTES.find(
    (r) =>
      r.methods.includes(method) &&
      r.path.length === path.length &&
      r.path.every((p, i) => (p === "*" ? !DOT_SEGMENTS.has(path[i]) : p === path[i])),
  );

// The routes the control plane lets a --ui-proxy call on a person's
// behalf. Every other route is called as the UI itself: the control
// plane refuses a person's token there.
const actsForPerson = (path: string[]) => path[0] === "v1" && path[1] === "policies";

const refuse = (status: number, error: string) =>
  Response.json({ error }, { status, headers: { "cache-control": "no-store" } });

// proxy forwards the routes above to the control plane. With sign-in
// configured it presents the signed-in person's JWT-SVID in
// Omega-User-Token next to the UI's own X.509-SVID on the policy API,
// and refuses a state-changing request that is cross-origin or, from a
// signed-in browser, lacks the session's CSRF token. A policy write
// without a live session gets 401 rather than being sent as the UI.
async function proxy(req: NextRequest, ctx: { params: Promise<{ path: string[] }> }) {
  const { path } = await ctx.params;
  const headers = strip(req.headers, REQUEST_ONLY);

  const r = route(req.method, path);
  if (!r) return refuse(404, "this UI does not forward that request");

  const auth = authState();
  if (auth.kind === "error") {
    return refuse(503, `this UI's sign-in is misconfigured: ${auth.error}`);
  }
  let signedIn = false;
  if (auth.kind === "on") {
    const unsafe = UNSAFE.has(req.method);
    if (unsafe && !sameOrigin(auth.config, req)) {
      return refuse(403, "cross-origin request refused");
    }
    if ((actsForPerson(path) || r.sessionOnly) && req.cookies.has(SESSION_COOKIE)) {
      const s = await currentSession(auth.config, req);
      if (s === "expired") return refuse(401, "your session has ended; sign in again");
      if (s) {
        if (unsafe && !csrfOK(s, req)) return refuse(403, "missing or wrong CSRF token");
        signedIn = true;
        if (actsForPerson(path)) headers.set(USER_TOKEN_HEADER, s.userToken);
      }
    }
  }
  if (r.signedIn && !headers.has(USER_TOKEN_HEADER)) {
    return refuse(401, "sign in to change policies");
  }
  if (r.sessionOnly && !signedIn && upstreamConfig().cert) {
    return refuse(401, "sign in to read the audit log");
  }

  const target = `/${path.map(encodeURIComponent).join("/")}${req.nextUrl.search}`;
  const body =
    req.method !== "GET" && req.method !== "HEAD"
      ? new Uint8Array(await req.arrayBuffer())
      : undefined;
  try {
    const upstream = await omegaRequest(req.method, target, headers, body);
    return new Response(upstream.body, {
      status: upstream.status,
      headers: strip(upstream.headers, RESPONSE_ONLY),
    });
  } catch (err) {
    return new Response(
      `upstream unreachable: ${upstreamConfig().url.origin} (${(err as Error).message})`,
      { status: 502, headers: { "content-type": "text/plain" } },
    );
  }
}

function strip(src: Headers, extra: Set<string>): Headers {
  const out = new Headers();
  src.forEach((value, key) => {
    const k = key.toLowerCase();
    if (!HOP_BY_HOP.has(k) && !extra.has(k)) out.append(key, value);
  });
  return out;
}

export {
  proxy as GET,
  proxy as POST,
  proxy as PUT,
  proxy as DELETE,
  proxy as PATCH,
  proxy as HEAD,
  proxy as OPTIONS,
};
