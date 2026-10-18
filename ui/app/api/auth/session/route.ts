import { type NextRequest, NextResponse } from "next/server";
import { authState } from "@/lib/server/config";
import { currentSession } from "@/lib/server/session";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

// GET /api/auth/session tells the page whether sign-in is configured
// and who is signed in, and hands it the CSRF token to send with every
// state-changing request. The person's JWT-SVID is never in the answer.
export async function GET(req: NextRequest) {
  const auth = authState();
  const headers = { "cache-control": "no-store" };
  if (auth.kind === "off") return NextResponse.json({ configured: false }, { headers });
  if (auth.kind === "error") {
    return NextResponse.json({ configured: false, error: auth.error }, { headers });
  }
  const s = await currentSession(auth.config, req);
  if (!s || s === "expired") {
    return NextResponse.json({ configured: true, expired: s === "expired" }, { headers });
  }
  return NextResponse.json(
    {
      configured: true,
      user: {
        spiffe_id: s.spiffeId,
        name: s.name,
        expires_at: new Date(s.tokenExpiresAt).toISOString(),
      },
      csrf: s.csrf,
    },
    { headers },
  );
}
