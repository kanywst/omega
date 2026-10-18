/**
 * Server-only sessions. A session lives in this process's memory and
 * the browser holds only its random id, in an httpOnly, Secure,
 * SameSite=Lax cookie. The user's JWT-SVID, the IdP refresh token and
 * the CSRF token never leave the server, except the CSRF token, which
 * the page reads from /api/auth/session and sends back in a header.
 *
 * In-memory means one UI replica, or sticky sessions in front of
 * several; a restart signs everyone out.
 */

import { timingSafeEqual } from "node:crypto";
import type { NextRequest } from "next/server";
import { z } from "zod";
import type { AuthConfig } from "./config";
import { checkIDToken, type IDClaims, random, refresh } from "./oidc";
import { omegaJSON } from "./upstream";

export const SESSION_COOKIE = "__Host-omega-session";
export const LOGIN_COOKIE = "__Host-omega-login";
export const CSRF_HEADER = "x-omega-csrf";
/** The header the control plane reads the user's JWT-SVID from (ADR 0023). */
export const USER_TOKEN_HEADER = "omega-user-token";

/** How long before its expiry a user token is renewed. */
const RENEW_BEFORE_MS = 60_000;
const LOGIN_TTL_MS = 10 * 60_000;
const MAX_SESSIONS = 10_000;
const MAX_LOGINS = 1_000;

export type Session = {
  id: string;
  csrf: string;
  spiffeId: string;
  name: string;
  userToken: string;
  tokenExpiresAt: number;
  refreshToken?: string;
  expiresAt: number;
  renewing?: Promise<Session | undefined>;
};

export type PendingLogin = {
  state: string;
  nonce: string;
  verifier: string;
  returnTo: string;
  expiresAt: number;
};

type Store = { sessions: Map<string, Session>; logins: Map<string, PendingLogin> };

// On globalThis so every route handler bundle shares one store.
const g = globalThis as typeof globalThis & { __omegaAuthStore?: Store };
if (!g.__omegaAuthStore) g.__omegaAuthStore = { sessions: new Map(), logins: new Map() };
const store: Store = g.__omegaAuthStore;

function prune<T extends { expiresAt: number }>(m: Map<string, T>, max: number) {
  const now = Date.now();
  for (const [k, v] of m) if (v.expiresAt <= now) m.delete(k);
  // Maps iterate in insertion order: drop the oldest past the cap.
  for (const k of m.keys()) {
    if (m.size < max) break;
    m.delete(k);
  }
}

export function startLogin(returnTo: string): PendingLogin {
  prune(store.logins, MAX_LOGINS);
  const login = {
    state: random(),
    nonce: random(),
    verifier: random(48),
    returnTo,
    expiresAt: Date.now() + LOGIN_TTL_MS,
  };
  store.logins.set(login.state, login);
  return login;
}

/** takeLogin returns the pending login for state once, if it has not expired. */
export function takeLogin(state: string): PendingLogin | undefined {
  const login = store.logins.get(state);
  store.logins.delete(state);
  return login && login.expiresAt > Date.now() ? login : undefined;
}

const Exchange = z.object({
  access_token: z.string().min(1),
  spiffe_id: z.string().min(1),
  expires_in: z.number().positive(),
});

/** exchangeIDToken swaps an ID token for the user's JWT-SVID at omega. */
async function exchangeIDToken(cfg: AuthConfig, idToken: string) {
  const { status, json } = await omegaJSON("/v1/oidc/exchange", {
    idp: cfg.idp,
    id_token: idToken,
    audience: [cfg.audience],
    ttl_seconds: cfg.tokenTTL,
  });
  if (status !== 200) {
    const err = (json as { error?: unknown }).error;
    throw new Error(
      `omega refused the ID token (${status}${typeof err === "string" && err ? `: ${err}` : ""})`,
    );
  }
  const ex = Exchange.parse(json);
  return {
    userToken: ex.access_token,
    spiffeId: ex.spiffe_id,
    tokenExpiresAt: Date.now() + ex.expires_in * 1000,
  };
}

const displayName = (c: IDClaims) => c.name ?? c.preferred_username ?? c.email ?? c.sub;

export async function createSession(
  cfg: AuthConfig,
  idToken: string,
  claims: IDClaims,
  refreshToken?: string,
): Promise<Session> {
  const ex = await exchangeIDToken(cfg, idToken);
  prune(store.sessions, MAX_SESSIONS);
  const s: Session = {
    id: random(),
    csrf: random(),
    name: displayName(claims),
    refreshToken,
    expiresAt: Date.now() + cfg.sessionMaxAge * 1000,
    ...ex,
  };
  store.sessions.set(s.id, s);
  return s;
}

export function endSession(id: string) {
  store.sessions.delete(id);
}

/**
 * currentSession returns the request's session, renewing the user's
 * JWT-SVID through the IdP's refresh token when it is about to expire.
 * A session that cannot be renewed ends. "expired" means the browser
 * presented a session cookie that no longer names a live session.
 */
export async function currentSession(
  cfg: AuthConfig,
  req: NextRequest,
): Promise<Session | "expired" | undefined> {
  const id = req.cookies.get(SESSION_COOKIE)?.value;
  if (!id) return undefined;
  const s = store.sessions.get(id);
  if (!s || s.expiresAt <= Date.now()) {
    store.sessions.delete(id);
    return "expired";
  }
  if (s.tokenExpiresAt - Date.now() > RENEW_BEFORE_MS) return s;
  s.renewing ??= renew(cfg, s).finally(() => {
    s.renewing = undefined;
  });
  return (await s.renewing) ?? "expired";
}

async function renew(cfg: AuthConfig, s: Session): Promise<Session | undefined> {
  if (s.refreshToken) {
    try {
      const tokens = await refresh(cfg, s.refreshToken);
      const claims = checkIDToken(cfg, tokens.id_token);
      const ex = await exchangeIDToken(cfg, tokens.id_token);
      if (ex.spiffeId !== s.spiffeId) {
        // The person must not change under a session.
        store.sessions.delete(s.id);
        return undefined;
      }
      Object.assign(s, ex, {
        name: displayName(claims),
        refreshToken: tokens.refresh_token ?? s.refreshToken,
      });
      return s;
    } catch {
      // The IdP or omega refused: do not ask again.
      s.refreshToken = undefined;
    }
  }
  // Without a renewal the token serves out its remaining time.
  if (s.tokenExpiresAt > Date.now() + 5_000) return s;
  store.sessions.delete(s.id);
  return undefined;
}

const sameSecret = (a: string, b: string) => {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
};

/**
 * sameOrigin checks a state-changing request comes from this UI's own
 * pages: its Origin is OMEGA_UI_URL's, or, without an Origin, the
 * browser marked it same-origin.
 */
export function sameOrigin(cfg: AuthConfig, req: NextRequest): boolean {
  const origin = req.headers.get("origin");
  if (origin) return origin === cfg.uiUrl.origin;
  return req.headers.get("sec-fetch-site") === "same-origin";
}

/** csrfOK checks the request carries the session's CSRF token. */
export function csrfOK(s: Session, req: NextRequest): boolean {
  const sent = req.headers.get(CSRF_HEADER);
  return !!sent && sameSecret(sent, s.csrf);
}

export const cookieOptions = (maxAgeSeconds: number) => ({
  httpOnly: true,
  secure: true,
  sameSite: "lax" as const,
  path: "/",
  maxAge: maxAgeSeconds,
});
