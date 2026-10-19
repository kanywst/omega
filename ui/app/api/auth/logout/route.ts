import { type NextRequest, NextResponse } from "next/server";
import { authState } from "@/lib/server/config";
import {
  cookieOptions,
  csrfOK,
  currentSession,
  endSession,
  SESSION_COOKIE,
  sameOrigin,
} from "@/lib/server/session";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

// POST /api/auth/logout ends the session here. The person's JWT-SVID is
// dropped with it; omega keeps no session of its own to end.
export async function POST(req: NextRequest) {
  const auth = authState();
  if (auth.kind !== "on") {
    return NextResponse.json({ error: "sign-in is not configured" }, { status: 404 });
  }
  if (!sameOrigin(auth.config, req)) {
    return NextResponse.json({ error: "cross-origin request refused" }, { status: 403 });
  }
  const s = await currentSession(auth.config, req);
  if (s && s !== "expired") {
    if (!csrfOK(s, req)) {
      return NextResponse.json({ error: "missing or wrong CSRF token" }, { status: 403 });
    }
    endSession(s.id);
  }
  const res = new NextResponse(null, { status: 204 });
  res.cookies.set(SESSION_COOKIE, "", cookieOptions(0));
  return res;
}
