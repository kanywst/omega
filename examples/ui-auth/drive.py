"""drive.py plays the browser for run-demo.sh.

It signs alice in to the UI (authorization code + PKCE against the mock
IdP, following the redirects by hand so every cookie is visible), then
manages a Cedar policy through the UI's /api/omega routes and checks the
audit chain. With a second replica's URL, it also checks that a login
started on one replica finishes on the other.
Usage: drive.py <ui-url> <alice-spiffe-id> <ui-spiffe-id> [<replica-url>]
"""

import http.client
import json
import sys
import time
import urllib.parse

UI, ALICE, UI_ID = sys.argv[1], sys.argv[2], sys.argv[3]
REPLICA = sys.argv[4] if len(sys.argv) > 4 else None
ORIGIN = UI

POLICY = 'permit (principal == Spiffe::"spiffe://omega.demo/media/web", action == Action::"read", resource);'
POLICY2 = 'permit (principal == Spiffe::"spiffe://omega.demo/media/web", action in [Action::"read", Action::"list"], resource);'


def request(method, url, body=None, headers=None, cookies=None):
    """One HTTP request, no redirects followed. Returns (status, headers, body)."""
    u = urllib.parse.urlsplit(url)
    conn = http.client.HTTPConnection(u.hostname, u.port, timeout=30)
    h = dict(headers or {})
    if cookies:
        h["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        h["Content-Type"] = "application/json"
    path = u.path + ("?" + u.query if u.query else "")
    conn.request(method, path, body=data, headers=h)
    resp = conn.getresponse()
    out = resp.read()
    conn.close()
    return resp.status, resp.headers, out


def set_cookies(headers):
    """The cookies a response sets, name -> value ("" when cleared)."""
    jar = {}
    for line in headers.get_all("Set-Cookie") or []:
        name, _, rest = line.partition("=")
        value = rest.split(";", 1)[0]
        attrs = line.lower()
        assert "httponly" in attrs and "secure" in attrs and "samesite=lax" in attrs, line
        jar[name] = value
    return jar


def check(cond, msg):
    if not cond:
        print(f"[drive] FAIL: {msg}", file=sys.stderr)
        sys.exit(1)
    print(f"[drive] ok: {msg}")


def jbody(raw):
    return json.loads(raw) if raw else {}


# Before sign-in the UI is read-only and acts as itself.
st, _, b = request("GET", f"{UI}/api/auth/session")
s = jbody(b)
check(st == 200 and s["configured"] and "user" not in s, "sign-in is configured and nobody is signed in")
st, _, b = request("POST", f"{UI}/api/omega/v1/policies", {"id": "demo", "text": POLICY}, {"Origin": ORIGIN})
check(st == 401, f"without sign-in the UI does not write policy ({st})")
st, _, _ = request("POST", f"{UI}/api/omega/v1/policies", {"id": "demo", "text": POLICY}, {"Origin": "https://evil.example"})
check(st == 403, "a cross-origin write is refused")
# The UI forwards only the calls its pages make, never other routes as itself.
st, _, _ = request("POST", f"{UI}/api/omega/v1/svid", {"spiffe_id": UI_ID, "csr": "x"}, {"Origin": ORIGIN})
check(st == 404, f"the UI does not forward SVID issuance ({st})")
st, _, _ = request("GET", f"{UI}/api/omega/v1/policies/%2e%2e/svid")
check(st == 404, f"a dot segment does not reach another route ({st})")

# Sign in: UI -> IdP -> UI callback.
st, h, _ = request("GET", f"{UI}/api/auth/login?return_to=/policies")
check(st == 302, f"login redirects to the IdP ({st})")
jar = set_cookies(h)
authorize = h["Location"]
q = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(authorize).query))
check(q.get("code_challenge_method") == "S256" and q.get("nonce") and q.get("state"), "the authorization request uses PKCE S256, a nonce and a state")
st, h, _ = request("GET", authorize)
check(st == 302, f"the IdP redirects back with a code ({st})")
callback = h["Location"]

# A callback without the login cookie that started the flow is refused.
st, h, _ = request("GET", callback)
check(st == 303 and "login_error" in h["Location"], "a callback from another browser does not sign in")

# Start again for the real sign-in, with a return_to that tries to leave the origin.
st, h, _ = request("GET", f"{UI}/api/auth/login?return_to=/%09/evil.example")
jar = set_cookies(h)
st, h, _ = request("GET", h["Location"])
st, h, _ = request("GET", h["Location"], cookies=jar)
check(st == 303 and h["Location"] == f"{UI}/", f"the callback signs in and stays on this origin ({st} {h['Location']})")
jar.update(set_cookies(h))
session_cookie = {"__Host-omega-session": jar["__Host-omega-session"]}

st, _, b = request("GET", f"{UI}/api/auth/session", cookies=session_cookie)
s = jbody(b)
check(s.get("user", {}).get("spiffe_id") == ALICE, f"signed in as {ALICE}")
check("eyJ" not in b.decode(), "the session answer carries no token")
csrf = s["csrf"]
write = {"Origin": ORIGIN, "X-Omega-CSRF": csrf}

# Writes as alice.
st, _, _ = request("POST", f"{UI}/api/omega/v1/policies", {"id": "demo", "text": POLICY}, {"Origin": ORIGIN}, session_cookie)
check(st == 403, "a write without the CSRF token is refused")
st, h, b = request("POST", f"{UI}/api/omega/v1/policies", {"id": "demo", "text": POLICY}, write, session_cookie)
check(st == 201, f"alice creates a policy ({st} {b[:200]!r})")
created = jbody(b)
check(created["created_by"] == ALICE, "created_by is alice")
etag = h["ETag"]

st, _, b = request("GET", f"{UI}/api/omega/v1/policies/demo", cookies=session_cookie)
check(st == 200 and jbody(b)["text"] == POLICY, "alice reads the text back")
st, _, b = request("GET", f"{UI}/api/omega/v1/policies/demo")
check(st == 403, "without a session the UI may not read the text")

# The mock IdP's ID tokens live 65s, so the user's JWT-SVID does too and
# is due for renewal (a minute before expiry) a few seconds from now:
# the UI renews it through the IdP's refresh token.
before = s["user"]["expires_at"]
time.sleep(6)
st, _, b = request("GET", f"{UI}/api/auth/session", cookies=session_cookie)
after = jbody(b).get("user", {})
check(after.get("spiffe_id") == ALICE and after.get("expires_at", "") > before, f"the session renews alice's token ({before} -> {after.get('expires_at')})")

st, _, _ = request("PUT", f"{UI}/api/omega/v1/policies/demo", {"text": POLICY2}, {**write, "If-Match": '"0-stale"'}, session_cookie)
check(st == 412, "an update with a stale ETag answers 412")
st, h, b = request("PUT", f"{UI}/api/omega/v1/policies/demo", {"text": POLICY2}, {**write, "If-Match": etag}, session_cookie)
check(st == 200 and jbody(b)["version"] == 2, f"alice updates the policy ({st})")
etag = h["ETag"]
st, _, _ = request("DELETE", f"{UI}/api/omega/v1/policies/demo", None, {**write, "If-Match": etag}, session_cookie)
check(st == 204, f"alice deletes the policy ({st})")

# Audit: every change names alice as actor and the UI as via.
st, _, _ = request("GET", f"{UI}/api/omega/v1/audit?limit=200")
check(st == 401, f"without a session the UI does not read the audit chain ({st})")
st, _, b = request("GET", f"{UI}/api/omega/v1/audit?limit=200", cookies=session_cookie)
check(st == 200, f"the audit chain is readable ({st})")
rows = {e["kind"]: e for e in jbody(b)["items"] if e["kind"].startswith("policy.") and e["decision"] == "ok"}
for kind in ("policy.create", "policy.update", "policy.delete"):
    ev = rows.get(kind)
    check(ev is not None and ev.get("actor") == ALICE and ev["payload"].get("via") == UI_ID, f"{kind} is audited as alice via the UI")

# Sign out ends the session; the cookie stops working.
st, _, _ = request("POST", f"{UI}/api/auth/logout", None, write, session_cookie)
check(st == 204, "sign out")
st, _, b = request("POST", f"{UI}/api/omega/v1/policies", {"id": "demo", "text": POLICY}, write, session_cookie)
check(st == 401, "the ended session no longer writes")

# A login started on one replica finishes on another that shares the
# login secret.
if REPLICA:
    st, h, _ = request("GET", f"{UI}/api/auth/login?return_to=/policies")
    jar = set_cookies(h)
    st, h, _ = request("GET", h["Location"])
    callback = urllib.parse.urlsplit(h["Location"])
    st, h, _ = request("GET", f"{REPLICA}{callback.path}?{callback.query}", cookies=jar)
    check(st == 303 and h["Location"] == f"{UI}/policies" and set_cookies(h).get("__Host-omega-session"), f"a login started on one replica finishes on another ({st} {h['Location']})")
