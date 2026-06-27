# SPIFFE federation between two Omega control planes

Two Omega trust domains (`omega.alpha` and `omega.beta`) federate so a
workload in either trust domain can validate an mTLS handshake against
the other. The demo proves the federation primitive end-to-end: each
side's agent serves the merged X.509 bundle map (own + peer) over the
SPIFFE Workload API.

## Topology

```text
                 +-------------------+   peer /v1/bundle   +-------------------+
                 |  omega.alpha      | <-----------------> |  omega.beta       |
                 |  control plane    |                     |  control plane    |
                 |  :18088           |                     |  :18089           |
                 +---------+---------+                     +---------+---------+
                           |                                         |
                           | /v1/federation/bundles                  |
                           v                                         v
                 +-------------------+                     +-------------------+
                 |  omega agent      |                     |  omega agent      |
                 |  alpha.sock       |                     |  beta.sock        |
                 +---------+---------+                     +---------+---------+
                           |  Workload API                           |
                           v  FetchX509Bundles                       v
                 {alpha: <CA>, beta: <CA>}                 {alpha: <CA>, beta: <CA>}
```

The control plane is the federation seam. The operator names every peer
explicitly with `--federate-with name=<peer-trust-domain>,url=<base>`;
the server then polls the peer's `/v1/bundle` endpoint and exposes the
merged map at `/v1/federation/bundles`. Agents read that endpoint and
hand the result straight to `FetchX509Bundles`, so workloads using
go-spiffe (or any conformant Workload API client) automatically gain
peer-domain trust.

## Run it

```bash
make demo
```

Expected output:

```text
[demo] starting omega.alpha on :18088 (federate-with omega.beta)
[demo] starting omega.beta on :18089 (federate-with omega.alpha)
[demo] starting omega.alpha agent (socket /tmp/omega-federation-demo/alpha.sock)
[demo] starting omega.beta agent (socket /tmp/omega-federation-demo/beta.sock)
[demo] building federation/check
[demo] expected fingerprints:
  omega.alpha: 3c2e62eaa3b098ce...
  omega.beta:  b428551806231255...
[demo] alpha agent bundle map:
  omega.alpha      sha256=3c2e62eaa3b098ce...
  omega.beta       sha256=b428551806231255...
[demo] beta agent bundle map:
  omega.alpha      sha256=3c2e62eaa3b098ce...
  omega.beta       sha256=b428551806231255...
[demo] success - both agents serve the merged trust bundle map
```

The script asserts that each agent reports the SHA-256 fingerprint of
the peer's actual CA (read directly from the peer's `/v1/bundle`), so a
mislabeled or stale entry would fail the run.

## What it proves

The classic two-step that proves federation is wired correctly:

1. The `/v1/federation/bundles` endpoint on each side carries both trust
   domains, with the peer entry's bytes equal to the peer's local
   `/v1/bundle`.
2. The agent's Workload API stream (`FetchX509Bundles`) hands the merged
   map to a go-spiffe `workloadapi.Client`, so a workload built on
   `tlsconfig.MTLSClientConfig(svidSrc, bundleSrc, ...)` will accept a
   peer SVID signed by the other trust domain's CA without any extra
   configuration on the workload itself.

The bundle exchange is one-way HTTP per peer. Two control planes
with `--federate-with` pointed at each other yields bidirectional
federation; chains of three or more work the same way.

## How peers are configured

Each control plane gets a repeatable `--federate-with` flag:

```bash
omega server \
  --http-addr 127.0.0.1:18088 --trust-domain omega.alpha \
  --federate-with name=omega.beta,url=http://127.0.0.1:18089 \
  --federation-allow-insecure
```

The fetch authenticates the peer's bundle endpoint, so peer URLs must be
`https://`. This loopback demo points two control planes at each other
over plaintext `http://`, which is only accepted because of the explicit
`--federation-allow-insecure` escape hatch (logged loudly at startup);
never use it outside a demo. For real federation use one of the SPIFFE
Federation profiles per peer:

- `profile=https_web` (default): standard web-PKI verification of the
  endpoint cert (system roots, or `endpoint_ca=<pem-file>`), with the
  usual hostname check.
- `profile=https_spiffe`: verify the endpoint's X.509-SVID against the
  pinned `endpoint_spiffe_id=spiffe://peer/...`, seeded from an
  out-of-band `endpoint_bundle=<pem-file>`.

The server fetches `<url>/v1/bundle` immediately on startup and then
every 30 seconds. A peer that is currently unreachable is omitted from
`/v1/federation/bundles` until the next successful fetch; a peer that
was previously reachable but is now down is served from cache, so a
short outage does not break in-flight handshakes.

## Known limitations

The current implementation is intentionally minimal. Three things land
before SPIFFE federation goes from "demonstrated" to "production":

| gap                        | what's missing                                                                                                               | follow-up                                                                                                    |
| -------------------------- | ---------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| Bundle authenticity        | Addressed: the fetch now requires `https://` and verifies the peer endpoint identity (`https_web` / `https_spiffe`). Plaintext `http://` only via `--federation-allow-insecure`. Remaining: persisting a `https_web`-TOFU seed across restarts. | Persist TOFU-seeded bundles in the store so trust-on-first-use is not re-run on every restart.     |
| JWKS federation            | Only X.509 bundles are exchanged today. JWT-SVID validation across trust domains needs the peer's JWKS too.                  | Extend `/v1/federation/bundles` with a JWKS section per trust domain alongside the OIDC federation hub work. |
| Bundle freshness signaling | Peers re-fetch on a fixed 30s timer. A rotated CA would propagate within that window but there is no push or refresh hint.   | Emit a `refresh_hint` per the SPIFFE Trust Domain and Bundle Format and have agents long-poll.               |

## Files

| path            | purpose                                                                                                |
| --------------- | ------------------------------------------------------------------------------------------------------ |
| `run-demo.sh`   | bring up two federated control planes + agents and assert the merged bundle map matches each side's CA |
| `Makefile`      | `make demo` / `make down` wrappers around `run-demo.sh`                                                |
| `check/main.go` | small Workload API client used by `run-demo.sh` to print each agent's `FetchX509Bundles` view          |
