# examples/spire-interop

Omega consuming a **real SPIRE deployment**: upstream `spire-server` and `spire-agent` images, real join-token node attestation, a real registration entry for omega, and SPIRE's own `localauthority` command driving the rotations.

[examples/spire-upstream-live](../spire-upstream-live/) proves omega speaks the SPIFFE Workload API, by serving that API from a mock. It is hermetic and fast, and it cannot make the claim that matters most here: that omega is an attestable workload of a real agent, and that it follows what that agent actually does. This example makes that claim and pays for it in Docker and about three minutes.

`make demo`:

1. starts `spire-server`, then bootstraps `spire-agent` against the server's trust bundle and a join token minted from the running server;
2. registers omega as a workload — `spiffe://upstream.demo/omega`, selected by the container label — because without an entry the agent does not answer it;
3. starts `omega server --identity-source-workload-api unix:///run/spire/sockets/agent.sock --identity-source-workload-api-jwt` and asserts `/v1/bundle` holds exactly the anchors `spire-server bundle show` reports, and `/v1/jwt/bundle` carries SPIRE's signing key;
4. asserts `POST /v1/svid`, `/v1/svid/jwt`, and `/v1/token/exchange` all return **501**;
5. rotates SPIRE's X.509 CA with `localauthority x509 prepare` + `activate`, asserts the prepared authority really became the active one, and then asserts omega's anchors follow with nothing signalling it;
6. rotates SPIRE's JWT signing key the same way and asserts `/v1/jwt/bundle` follows;
7. asserts `spiffe_sequence` advanced across both.

Step 5 activates rather than only preparing. `prepare` alone adds the new authority to the bundle, which omega would follow without anything having rotated; asserting that the prepared authority became active is what makes it a rotation test.

Sample success output:

```text
[demo] starting spire-server
[demo] bootstrapping the agent against the server's trust bundle
[demo] registering omega as a workload of that trust domain
[demo] starting spire-agent
[demo] starting omega against the agent's workload API socket
[demo] omega serves SPIRE's trust anchors
[demo]   ok: /v1/bundle == spire-server bundle show (a3c6534213b955e8)
[demo]   ok: /v1/jwt/bundle carries SPIRE's signing key (jRwIRKVNNoFb7sB8IKwfGZvwqKNAu4Vp)
[demo]   ok: spiffe_sequence starts at 1 (1)
[demo] issuance routes stay disabled (no local CA)
[demo]   ok: POST /v1/svid (501)
[demo] rotating SPIRE's X.509 CA — omega is not told
[demo]   ok: SPIRE promoted the prepared X.509 authority (62d980391716b3a3)
[demo]   ok: /v1/bundle followed SPIRE's CA rotation, with no signal sent
[demo] rotating SPIRE's JWT signing key — omega is not told
[demo]   ok: SPIRE promoted the prepared JWT authority (GU1WWXYSTJA33Nze)
[demo]   ok: /v1/jwt/bundle followed the signing-key rotation
[demo]   ok: spiffe_sequence advanced to 3
[demo] success — omega consumed a real SPIRE rotation with no operator in the loop
```

## Run

```text
make demo
```

The script tears itself down on exit; force a manual cleanup:

```text
make down
```

## Requirements

- Docker with Compose. Nothing else: omega is built from the repo `Dockerfile`, and SPIRE comes from `ghcr.io/spiffe/spire-{server,agent}:1.15.3`.
- `curl` and `python3`.

## What real SPIRE forced into the open

Three things the mock could not have taught, all now visible in `compose.yaml` and `conf/`:

- **`jwt_key_type = "ec-p256"` on the server.** SPIRE's JWT signing key follows `ca_key_type`, and omega consumes only EC P-256 (ES256) signing keys. On an RSA upstream, `--identity-source-workload-api-jwt` has no usable key and startup fails closed. This is the one place a real deployment has to meet omega halfway.
- **omega needs a registration entry.** The agent answers the Workload API only for callers it can attest. Without an entry omega gets `PermissionDenied` and does not start, which is the correct behaviour and worth seeing once.
- **The agent needs the host PID namespace.** The workload attestors resolve a caller from the pid `SO_PEERCRED` reports, which only means something in a namespace the agent can see. Without it every call fails with `could not resolve caller information` — the agent is answering, it just cannot tell who is asking.

## What this demo does not do

The join-token node attestor and the root-run containers are demo shape, not deployment advice. A real deployment uses a platform node attestor (`k8s_psat`, `aws_iid`, `x509pop`), keeps the distroless users, and gives the agent socket a group omega can read rather than running omega as root. None of that changes the omega side: the flags are the same.
