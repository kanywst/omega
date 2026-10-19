/**
 * Server-only OpenID Connect relying party: the authorization code flow
 * with PKCE (RFC 7636, S256) and the refresh_token grant.
 *
 * The ID token comes straight from the token endpoint over TLS, so its
 * signature is not checked here (OIDC Core 3.1.3.7, item 6): omega
 * checks it against the IdP's JWKS when the UI exchanges the token at
 * POST /v1/oidc/exchange. This module checks what omega does not: the
 * nonce that binds the token to this login.
 */

import { createHash, randomBytes } from "node:crypto";
import { z } from "zod";
import type { AuthConfig } from "./config";

const Discovery = z.object({
  issuer: z.string(),
  authorization_endpoint: z.string().url(),
  token_endpoint: z.string().url(),
});
type Discovery = z.infer<typeof Discovery>;

const TokenResponse = z.object({
  id_token: z.string().min(1),
  refresh_token: z.string().optional(),
});
export type Tokens = z.infer<typeof TokenResponse>;

const IDClaims = z.object({
  iss: z.string(),
  aud: z.union([z.string(), z.array(z.string())]),
  exp: z.number(),
  sub: z.string(),
  nonce: z.string().optional(),
  name: z.string().optional(),
  preferred_username: z.string().optional(),
  email: z.string().optional(),
});
export type IDClaims = z.infer<typeof IDClaims>;

export const random = (bytes = 32) => randomBytes(bytes).toString("base64url");
export const pkceChallenge = (verifier: string) =>
  createHash("sha256").update(verifier).digest("base64url");

let discovered: { issuer: string; doc: Discovery; at: number } | undefined;

async function discover(cfg: AuthConfig): Promise<Discovery> {
  if (discovered?.issuer === cfg.issuer && Date.now() - discovered.at < 5 * 60_000) {
    return discovered.doc;
  }
  const res = await fetch(`${cfg.issuer}/.well-known/openid-configuration`, { cache: "no-store" });
  if (!res.ok) throw new Error(`OIDC discovery answered ${res.status}`);
  const doc = Discovery.parse(await res.json());
  if (doc.issuer.replace(/\/+$/, "") !== cfg.issuer) {
    throw new Error(`OIDC discovery names issuer ${doc.issuer}, not ${cfg.issuer}`);
  }
  // An https issuer must not send the browser, the code or the client
  // secret over plain HTTP.
  if (cfg.issuer.startsWith("https:")) {
    for (const [name, url] of [
      ["authorization", doc.authorization_endpoint],
      ["token", doc.token_endpoint],
    ]) {
      if (!url.startsWith("https:")) {
        throw new Error(`OIDC discovery names a ${name} endpoint that is not https://`);
      }
    }
  }
  discovered = { issuer: cfg.issuer, doc, at: Date.now() };
  return doc;
}

export const redirectURI = (cfg: AuthConfig) => new URL("/api/auth/callback", cfg.uiUrl).href;

export async function authorizeURL(
  cfg: AuthConfig,
  p: { state: string; nonce: string; verifier: string },
): Promise<string> {
  const doc = await discover(cfg);
  const url = new URL(doc.authorization_endpoint);
  url.search = new URLSearchParams({
    response_type: "code",
    client_id: cfg.clientId,
    redirect_uri: redirectURI(cfg),
    scope: cfg.scopes,
    state: p.state,
    nonce: p.nonce,
    code_challenge: pkceChallenge(p.verifier),
    code_challenge_method: "S256",
  }).toString();
  return url.href;
}

async function tokenRequest(cfg: AuthConfig, form: Record<string, string>): Promise<Tokens> {
  const doc = await discover(cfg);
  const body = new URLSearchParams(form);
  const headers: Record<string, string> = {
    "content-type": "application/x-www-form-urlencoded",
    accept: "application/json",
  };
  if (cfg.clientSecret) {
    // client_secret_basic (RFC 6749 2.3.1): both parts form-encoded.
    const enc = (s: string) => encodeURIComponent(s).replace(/%20/g, "+");
    headers.authorization = `Basic ${Buffer.from(`${enc(cfg.clientId)}:${enc(cfg.clientSecret)}`).toString("base64")}`;
  } else {
    body.set("client_id", cfg.clientId);
  }
  const res = await fetch(doc.token_endpoint, {
    method: "POST",
    headers,
    body,
    cache: "no-store",
    redirect: "error",
  });
  const json = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = (json as { error?: unknown }).error;
    throw new Error(
      `token endpoint answered ${res.status}${typeof err === "string" ? ` (${err})` : ""}`,
    );
  }
  return TokenResponse.parse(json);
}

export const redeemCode = (cfg: AuthConfig, code: string, verifier: string) =>
  tokenRequest(cfg, {
    grant_type: "authorization_code",
    code,
    redirect_uri: redirectURI(cfg),
    code_verifier: verifier,
  });

export const refresh = (cfg: AuthConfig, refreshToken: string) =>
  tokenRequest(cfg, { grant_type: "refresh_token", refresh_token: refreshToken });

/**
 * checkIDToken reads the ID token's claims and checks the issuer, the
 * audience, the expiry and, on a login, the nonce. A refreshed ID token
 * carries no nonce, or the one from the login (OIDC Core 12.2).
 */
export function checkIDToken(cfg: AuthConfig, idToken: string, nonce?: string): IDClaims {
  const parts = idToken.split(".");
  if (parts.length !== 3) throw new Error("the ID token is not a JWS");
  const claims = IDClaims.parse(JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8")));
  const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (claims.iss.replace(/\/+$/, "") !== cfg.issuer)
    throw new Error("the ID token's iss is not the issuer");
  if (!aud.includes(cfg.clientId)) throw new Error("the ID token is not for this client");
  if (claims.exp * 1000 <= Date.now()) throw new Error("the ID token has expired");
  if (nonce !== undefined && claims.nonce !== nonce)
    throw new Error("the ID token's nonce does not match the login");
  return claims;
}
