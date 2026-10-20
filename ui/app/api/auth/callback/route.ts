import { type NextRequest, NextResponse } from "next/server";
import { authState } from "@/lib/server/config";
import { checkIDToken, redeemCode } from "@/lib/server/oidc";
import {
  cookieOptions,
  createSession,
  LOGIN_COOKIE,
  SESSION_COOKIE,
  takeLogin,
} from "@/lib/server/session";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

// GET /api/auth/callback finishes the login: it checks the state against
// the login this browser started, redeems the code with the PKCE
// verifier, checks the ID token's nonce, and exchanges the ID token at
// omega for the person's JWT-SVID, which stays in the server-side
// session. Any failure lands back on the UI with login_error set and no
// session.
export async function GET(req: NextRequest) {
  const auth = authState();
  if (auth.kind !== "on") {
    return NextResponse.json({ error: "sign-in is not configured" }, { status: 404 });
  }
  const cfg = auth.config;
  const q = req.nextUrl.searchParams;
  const state = q.get("state") ?? "";
  const login = takeLogin(cfg, state, req.cookies.get(LOGIN_COOKIE)?.value);

  const done = (path: string, error?: string) => {
    const url = new URL(path, cfg.uiUrl);
    if (error) url.searchParams.set("login_error", error);
    const res = NextResponse.redirect(url, 303);
    res.cookies.set(LOGIN_COOKIE, "", cookieOptions(0));
    res.headers.set("cache-control", "no-store");
    return res;
  };

  if (!login) return done("/", "the sign-in expired or was not started here; try again");
  const idpError = q.get("error");
  if (idpError) return done(login.returnTo, `the IdP answered ${idpError}`);
  const code = q.get("code");
  if (!code) return done(login.returnTo, "the IdP sent no authorization code");

  try {
    const tokens = await redeemCode(cfg, code, login.verifier);
    const claims = checkIDToken(cfg, tokens.id_token, login.nonce);
    const s = await createSession(cfg, tokens.id_token, claims, tokens.refresh_token);
    const res = done(login.returnTo);
    res.cookies.set(SESSION_COOKIE, s.id, cookieOptions(cfg.sessionMaxAge));
    return res;
  } catch (err) {
    return done(login.returnTo, (err as Error).message);
  }
}
