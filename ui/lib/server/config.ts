/**
 * Server-only configuration of the UI's sign-in and its connection to
 * the control plane, read from the environment.
 *
 * Sign-in is on when OMEGA_UI_OIDC_ISSUER is set. Then every other
 * setting it needs must be set too: a partial configuration is an
 * error, and the UI stays read-only rather than guessing.
 */

export type UpstreamConfig = {
  url: URL;
  ca?: string;
  cert?: string;
  key?: string;
};

export type AuthConfig = {
  /** Public origin of this UI; the redirect URI and the CSRF origin check derive from it. */
  uiUrl: URL;
  issuer: string;
  clientId: string;
  clientSecret?: string;
  scopes: string;
  /** The --oidc-idp name omega validates the ID token against. */
  idp: string;
  /** The --ui-proxy-audience the user's JWT-SVID is requested for. */
  audience: string;
  /** Requested lifetime of the user's JWT-SVID, in seconds. */
  tokenTTL: number;
  /** Longest a session lasts, refreshes included, in seconds. */
  sessionMaxAge: number;
  /** Secret the login cookie is sealed with; unset, each process makes its own. */
  loginSecret?: string;
};

const env = (name: string) => process.env[name]?.trim() || undefined;

export function upstreamConfig(): UpstreamConfig {
  return {
    url: new URL(env("OMEGA_API") ?? "http://127.0.0.1:8080"),
    ca: env("OMEGA_API_CA"),
    cert: env("OMEGA_API_CLIENT_CERT"),
    key: env("OMEGA_API_CLIENT_KEY"),
  };
}

export type AuthState =
  | { kind: "off" }
  | { kind: "error"; error: string }
  | { kind: "on"; config: AuthConfig };

export function authState(): AuthState {
  const issuer = env("OMEGA_UI_OIDC_ISSUER");
  if (!issuer) return { kind: "off" };
  const missing = ["OMEGA_UI_URL", "OMEGA_UI_OIDC_CLIENT_ID", "OMEGA_UI_OIDC_IDP"].filter(
    (n) => !env(n),
  );
  const upstream = upstreamConfig();
  if (!upstream.cert) missing.push("OMEGA_API_CLIENT_CERT");
  if (!upstream.key) missing.push("OMEGA_API_CLIENT_KEY");
  if (missing.length > 0) {
    return { kind: "error", error: `sign-in is configured but ${missing.join(", ")} is not set` };
  }
  if (upstream.url.protocol !== "https:") {
    return { kind: "error", error: "sign-in needs OMEGA_API to be an https:// URL (mTLS)" };
  }
  let uiUrl: URL;
  try {
    uiUrl = new URL(env("OMEGA_UI_URL")!);
  } catch {
    return { kind: "error", error: "OMEGA_UI_URL is not a URL" };
  }
  if (!secureOrLocal(uiUrl)) {
    return { kind: "error", error: "OMEGA_UI_URL must be https:// outside localhost" };
  }
  // The token endpoint comes from the issuer's discovery document, and
  // the ID token's signature is checked only by omega, so the issuer
  // must be reached over TLS.
  let issuerUrl: URL;
  try {
    issuerUrl = new URL(issuer);
  } catch {
    return { kind: "error", error: "OMEGA_UI_OIDC_ISSUER is not a URL" };
  }
  if (!secureOrLocal(issuerUrl)) {
    return { kind: "error", error: "OMEGA_UI_OIDC_ISSUER must be https:// outside localhost" };
  }
  const loginSecret = env("OMEGA_UI_LOGIN_SECRET");
  if (loginSecret !== undefined && loginSecret.length < 32) {
    return { kind: "error", error: "OMEGA_UI_LOGIN_SECRET must be at least 32 characters" };
  }
  const tokenTTL = positiveInt("OMEGA_UI_TOKEN_TTL", 900);
  const sessionMaxAge = positiveInt("OMEGA_UI_SESSION_MAX_AGE", 8 * 3600);
  if (tokenTTL === undefined || sessionMaxAge === undefined) {
    return {
      kind: "error",
      error: "OMEGA_UI_TOKEN_TTL and OMEGA_UI_SESSION_MAX_AGE must be positive integers",
    };
  }
  return {
    kind: "on",
    config: {
      uiUrl,
      issuer: issuer.replace(/\/+$/, ""),
      clientId: env("OMEGA_UI_OIDC_CLIENT_ID")!,
      clientSecret: env("OMEGA_UI_OIDC_CLIENT_SECRET"),
      scopes: env("OMEGA_UI_OIDC_SCOPES") ?? "openid profile email",
      idp: env("OMEGA_UI_OIDC_IDP")!,
      audience: env("OMEGA_UI_TOKEN_AUDIENCE") ?? "omega-ui",
      tokenTTL,
      sessionMaxAge,
      loginSecret,
    },
  };
}

function secureOrLocal(u: URL): boolean {
  const local = u.hostname === "localhost" || u.hostname === "127.0.0.1" || u.hostname === "[::1]";
  return u.protocol === "https:" || (u.protocol === "http:" && local);
}

function positiveInt(name: string, fallback: number): number | undefined {
  const raw = env(name);
  if (raw === undefined) return fallback;
  const n = Number(raw);
  return Number.isInteger(n) && n > 0 ? n : undefined;
}
