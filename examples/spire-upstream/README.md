# examples/spire-upstream

End-to-end demo of the `spire-upstream` identity source: omega consumes
SPIFFE identities minted by an upstream trust domain (SPIRE / Istio)
instead of issuing its own, serving only the authorization and audit
layer over upstream-issued SVIDs. It covers the three ADRs that build
that path — [0007](../../docs/adr/0007-pluggable-identity-source.md)
(non-issuing source),
[0008](../../docs/adr/0008-upstream-jwt-svid-validation.md) (consume the
upstream JWKS), and
[0009](../../docs/adr/0009-upstream-trust-material-reload.md) (reload on
SIGHUP).

The regression this guards is silent and time-delayed. Upstream SPIRE
rotates its CA and JWT signing key on its own schedule; a control plane
that read the bundle once at boot keeps serving anchors that no longer
cover freshly-issued upstream SVIDs. Nothing fails at boot or in a
health check, and agents cache whatever the control plane hands them, so
the staleness fans out across the deployment instead of self-correcting.

`make demo`:

1. mints two upstream generations by booting a throwaway built-in
   `omega server` twice and harvesting `/v1/bundle` + `/v1/jwt/bundle`
   from each, asserting the two really differ (a fixture that shared a
   CA or a `kid` would prove nothing);
2. boots `omega server --identity-source spire-upstream` against
   generation `a` and asserts `/v1/bundle` is the upstream PEM verbatim,
   `/v1/jwt/bundle` carries the upstream `kid`, and `spiffe_sequence`
   is `1`;
3. asserts `POST /v1/svid`, `/v1/svid/jwt`, and `/v1/token/exchange` all
   return **501** — this source runs no CA;
4. corrupts the bundle file and sends `SIGHUP`, asserting omega **keeps
   serving generation `a`** and does not advance the sequence;
5. rotates both files to generation `b`, sends `SIGHUP`, and asserts the
   served anchors, the JWKS `kid`, and `spiffe_sequence` all follow;
6. sends a final `SIGHUP` with nothing changed and asserts the sequence
   stays put.

Sample success output:

```text
[demo] minting two upstream generations (a CA rotation)
[demo]   generation a kids: H8u1mXlJIdw
[demo]   generation b kids: QYxTQTDLvNE
[demo] serving the upstream trust material (generation a)
[demo]   ok: /v1/bundle == upstream generation a
[demo]   ok: /v1/jwt/bundle serves the upstream signing keys (H8u1mXlJIdw)
[demo]   ok: spiffe_sequence starts at 1 (1)
[demo] issuance routes stay disabled (no local CA)
[demo]   ok: POST /v1/svid (501)
[demo] SIGHUP with a corrupt bundle (fail-closed)
[demo]   ok: still serving generation a after a rejected reload
[demo]   ok: spiffe_sequence did not advance (1)
[demo] rotating the upstream to generation b, then SIGHUP
[demo]   ok: /v1/bundle == upstream generation b
[demo]   ok: /v1/jwt/bundle follows the signing-key rotation (QYxTQTDLvNE)
[demo]   ok: spiffe_sequence advanced (2)
[demo] SIGHUP with unchanged material (no-op)
[demo]   ok: spiffe_sequence stayed put (2)
[demo] success — consumed an upstream rotation without a restart
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

- `omega` on `$PATH` (the repo `make build` puts it under `./bin`; the
  parent CI matrix exports that path for the demo).
- `curl` and `python3`.

## Why a throwaway omega stands in for SPIRE

The demo needs an upstream that emits a SPIFFE trust bundle and an EC
P-256 JWKS, twice, with different key material each time. A built-in
`omega server` on a temp data dir produces exactly that and keeps the
example dependency-free — omega only ever *consumes* this material, so
what generated it is immaterial. Against a real SPIRE the operator
points the two flags at the upstream's bundle and JWKS instead.

## What this demo is not

It is not a SPIRE interop certificate. It proves omega's consuming side
behaves — non-issuing, JWKS-serving, rotation-following, fail-closed —
against material shaped like an upstream's. Wiring to a live SPIRE is a
deployment concern; the flags are the same either way.

Reload on this transport is deliberately operator-driven: omega does not
watch the files, because the signal is where the operator asserts a swap
— often of two files — is complete, and watching would race a
half-applied rotation.

Omega can instead follow the upstream's SPIFFE Workload API socket, where
a rotation needs no operator at all; see
[examples/spire-upstream-live](../spire-upstream-live/) and
[ADR 0010](../../docs/adr/0010-live-upstream-trust-material.md). The file
transport stays the default because it adds no runtime dependency on the
upstream.
