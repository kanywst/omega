# examples/spire-upstream-live

The live transport for the `spire-upstream` identity source: omega follows the upstream trust domain's SPIFFE Workload API socket, so a CA or JWT signing-key rotation reaches it with no operator in the loop. See [ADR 0010](../../docs/adr/0010-live-upstream-trust-material.md).

[examples/spire-upstream](../spire-upstream/) covers the file transport, where the operator swaps `--identity-source-bundle` / `--identity-source-jwt-bundle` and sends `SIGHUP`. That leaves the operator owning the half that notices the rotation, usually a hand-written sidecar watching SPIRE. When the sidecar dies quietly, omega serves anchors that no longer cover freshly-issued upstream SVIDs, nothing fails at boot or in a health check, and agents cache the staleness rather than recovering from it.

`make demo`:

1. mints two upstream generations by booting a throwaway built-in `omega server` twice and harvesting `/v1/bundle` + `/v1/jwt/bundle` from each, asserting the two really differ (a fixture that shared a CA or a `kid` would prove nothing);
2. boots `mock-spire-agent`, a SPIFFE Workload API socket serving generation `a`;
3. boots `omega server --identity-source-workload-api unix://.../agent.sock --identity-source-workload-api-jwt` and asserts `/v1/bundle` is the upstream PEM verbatim, `/v1/jwt/bundle` carries the upstream `kid`, and `spiffe_sequence` is `1`;
4. asserts `POST /v1/svid`, `/v1/svid/jwt`, and `/v1/token/exchange` all return **501** — the transport changed, the issuance posture did not;
5. rotates the upstream to generation `b` and signals nothing, then asserts the served anchors, the JWKS `kid`, and `spiffe_sequence` all follow anyway;
6. makes the upstream stop publishing the trust domain and asserts omega keeps serving generation `b` without advancing the sequence.

Step 5 is what separates this from the sibling demo: no `SIGHUP`, no restart, no request to omega. The only thing that changed is what the upstream publishes.

Sample success output:

```text
[demo] minting two upstream generations (a CA + signing-key rotation)
[demo]   generation a kids: tFNvjKqwf6g
[demo]   generation b kids: ddE1vSxJiQ0
[demo] starting the upstream workload API socket
[demo] starting omega following that socket on :18893
[demo]   ok: /v1/bundle == upstream generation a
[demo]   ok: /v1/jwt/bundle serves the upstream signing keys (tFNvjKqwf6g)
[demo]   ok: spiffe_sequence starts at 1 (1)
[demo] issuance routes stay disabled (no local CA)
[demo]   ok: POST /v1/svid (501)
[demo] rotating the upstream to generation b — omega is not told
[demo]   ok: /v1/bundle == upstream generation b, with no signal sent
[demo]   ok: /v1/jwt/bundle followed the signing-key rotation (ddE1vSxJiQ0)
[demo]   ok: spiffe_sequence advanced to 3
[demo] upstream stops publishing the trust domain (fail-closed)
[demo]   ok: still serving generation b
[demo]   ok: spiffe_sequence did not advance (3)
[demo] success — consumed an upstream rotation with no operator in the loop
```

`spiffe_sequence` lands on `3` rather than `2` because the X.509 and JWT bundles arrive on independent streams, and each is a real change to the served material. Peers use the sequence to decide whether to re-read, so an extra increment costs one re-read.

## Run

```text
make demo
```

The script tears itself down on exit; force a manual cleanup:

```text
make down
```

## Requirements

- `omega` on `$PATH` (the repo `make build` puts it under `./bin`; the parent CI matrix exports that path for the demo).
- A Go toolchain, to build `mock-spire-agent`.
- `curl` and `python3`.

## Against a real SPIRE

The flags are the same; only the socket path changes:

```text
omega server \
  --identity-source spire-upstream \
  --trust-domain example.org \
  --identity-source-workload-api unix:///run/spire/sockets/agent.sock \
  --identity-source-workload-api-jwt
```

The address must be `unix://`. A network endpoint is dialled without transport security, so anything on the path could hand omega its trust anchors; see [ADR 0010](../../docs/adr/0010-live-upstream-trust-material.md).

Two deployment facts this demo does not cover, both exercised against upstream SPIRE images in [examples/spire-interop](../spire-interop/):

- **omega must be an attested workload of that agent.** SPIRE answers the Workload API only for callers it can attest, so the control-plane process needs a registration entry (typically a `unix:uid:` or `k8s:` selector). Without one, startup fails with a `PermissionDenied` from the socket.
- **`--identity-source-workload-api-jwt` needs an EC P-256 JWT signing key upstream.** omega consumes only ES256 signing keys, so a SPIRE server configured with `jwt_key_type = "rsa-2048"` has no usable key and startup fails closed. Leave the flag off for X.509-only consumption, or set `jwt_key_type = "ec-p256"` on the SPIRE server.

## Why a mock agent

Same reason as [`mock-step-ca`](../ca-step-ca/mock-step-ca/) and the mock Vault: the demo stays hermetic and fast enough to run on every PR, and the assertions stay pointed at the omega side of the wire.

The wire is not mocked. `mock-spire-agent` implements the upstream SPIFFE `SpiffeWorkloadAPI` service from the same protobuf definitions SPIRE serves, and enforces the `workload.spiffe.io: true` security header SPIRE requires, so a regression in omega's Workload API client trips this demo.

What it cannot cover is the SPIRE-specific deployment surface — attestation, entry registration, key-type configuration — which is why [examples/spire-interop](../spire-interop/) exists alongside it and runs the same assertions against real `spire-server` and `spire-agent` images. This one stays because it is hermetic and finishes in seconds, so it is the demo that catches a Workload API client regression first.
