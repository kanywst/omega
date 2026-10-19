import { type NextRequest, NextResponse } from "next/server";
import { authState } from "@/lib/server/config";
import { authorizeURL } from "@/lib/server/oidc";
import { cookieOptions, LOGIN_COOKIE, startLogin } from "@/lib/server/session";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

// safeReturnTo keeps the post-login redirect on this UI: a path, never
// another origin. It resolves the path the way the callback will, since
// the URL parser drops tabs and newlines ("/\t/evil.example" becomes
// "//evil.example").
function safeReturnTo(raw: string | null): string {
  if (!raw?.startsWith("/")) return "/";
  const base = "http://ui.invalid";
  const url = new URL(raw, base);
  if (url.origin !== base) return "/";
  return url.pathname + url.search + url.hash;
}

// GET /api/auth/login starts the authorization code flow with PKCE. The
// state is bound to this browser by a short-lived cookie, so a login
// another site starts cannot be completed in this browser.
export async function GET(req: NextRequest) {
  const auth = authState();
  if (auth.kind !== "on") {
    return NextResponse.json(
      { error: auth.kind === "off" ? "sign-in is not configured" : auth.error },
      { status: 404 },
    );
  }
  const login = startLogin(safeReturnTo(req.nextUrl.searchParams.get("return_to")));
  let location: string;
  try {
    location = await authorizeURL(auth.config, login);
  } catch (err) {
    return NextResponse.json(
      { error: `cannot reach the IdP: ${(err as Error).message}` },
      { status: 502 },
    );
  }
  const res = NextResponse.redirect(location, 302);
  res.cookies.set(LOGIN_COOKIE, login.state, cookieOptions(600));
  res.headers.set("cache-control", "no-store");
  return res;
}
