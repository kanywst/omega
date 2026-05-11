# ADR 0005: Authority interface as the CA backend plugin seam

## Status

Accepted.

## Context

[`docs/design-philosophy.md`](../design-philosophy.md) puts the CA
upstream in the Plugin layer:

> CA upstream (self-signed default; Vault PKI / step-ca / AWS PCA /
> GCP CAS / Azure Key Vault)

But until this ADR existed, there was no contract that captured
*how* a non-default backend slots in. New backends were a series
of one-off PRs without a reference shape, and the gap surfaced
during external review (gap-analysis.md §1.4).

omega already has the right interface in
[`internal/server/identity/authority.go`](../../internal/server/identity/authority.go) -
`Authority` is issuance-only on purpose - and the default
disk-backed implementation lives next to it. The decision to be
recorded is not a refactor; it is the commitment that this
interface *is* the seam, and that future backends slot in by
adding a new `Kind` to `Config` rather than by introducing a
parallel constructor.

## Decision

The `identity.Authority` interface is the omega Plugin-layer
contract for CA backends. Every backend must satisfy it:

```go
type Authority interface {
    TrustDomain() spiffeid.TrustDomain
    BundlePEM() []byte

    IssueSVID(id spiffeid.ID, pub crypto.PublicKey) (*SVID, error)

    IssueJWTSVID(id spiffeid.ID, audience []string, ttl time.Duration, extraClaims map[string]any) (*JWTSVID, error)
    JWTKeyID() (string, error)
    JWTBundle() ([]byte, error)
    IssuerURL() string
    ValidateJWTSVID(token, audience string) (spiffeid.ID, error)
    ValidatePresentedCertBinding(token, audience string, presented *x509.Certificate) (spiffeid.ID, error)
    ParseJWTSVIDClaims(token string) (spiffeid.ID, map[string]any, error)
}
```

New backends register themselves by:

1. adding a `Kind` constant (e.g. `KindVaultPKI`, `KindAWSPCA`,
   `KindGCPCAS`, `KindAzureKV`, `KindStepCA`, `KindPKCS11`);
2. adding the backend-specific fields to `Config` (URLs, ARNs,
   slot URIs, etc.);
3. extending the `switch cfg.Kind` in `identity.New` to construct
   the new backend;
4. shipping a `*<backend>Authority` struct that implements every
   method on the interface.

The implementation step-by-step is the subject of the companion
guide at [`docs/ca-plugin-guide.md`](../ca-plugin-guide.md).

Issuance-only is deliberate. Management concerns (CA rotation,
key escrow, audit replay) live outside the interface so an
HSM-backed backend does not have to expose private key material
to implement them. Key rotation is an operator workflow on the
backend (rotate the KMS key, mint a new bundle, propagate via
`/v1/bundle` and federation); omega does not orchestrate it.

The default disk backend stays in-tree as the quickstart-friendly
zero-config option. Production deployments are expected to swap
in a KMS-backed backend; we do not deprecate disk because the
single-binary demo path depends on it.

## Consequences

Easier:

- A new backend is one Kind + one struct + one `switch` case. No
  parallel constructors, no shadow API.
- An HSM / KMS backend keeps the private key out of process
  memory by satisfying the interface against a remote signer
  (the methods take public keys + claims and return signed
  artefacts; the implementation can delegate every signature to
  the upstream).
- Operators can audit the seam: `identity.Authority` is the only
  surface the rest of the server depends on for CA work.

Harder:

- The interface is intentionally narrow; backends that want to
  expose extra capabilities (e.g. KMS-side rotation hooks) have
  to either (a) keep them internal, (b) propose an interface
  amendment via a follow-up ADR, or (c) expose them through a
  separate HTTP surface.
- Adding a new method to `Authority` is a breaking change for
  every backend, including third-party out-of-tree ones. Treat
  the interface as 1.0-stability adjacent even pre-1.0.

New obligations:

- Each in-tree backend gets a smoke test that exercises every
  interface method against the live backend (or a high-fidelity
  fake). The disk backend's `internal/server/identity/*_test.go`
  files are the reference shape.
- The plugin guide stays accurate. Reviewers will ask for guide
  updates on every Plugin-layer ADR.

## Scope fit

Rule 3 in [design-philosophy.md](../design-philosophy.md):
*"Is it an upstream system Omega depends on but does not own?"*

Yes. CA backends are exactly that. The interface is Core
(omega-owned), individual backends are Plugin (omega defines the
seam and ships the disk default; everything else is an
implementation choice).

## Implementation pointers

- Reference implementation: `internal/server/identity/authority.go`
  (`localAuthority`).
- Reference test pattern: `internal/server/identity/authority_test.go`
  and `internal/server/identity/jwt_test.go`.
- CLI wiring: a new Kind needs a flag (e.g. `--ca-backend=kms`)
  plus per-Kind config flags. The disk backend uses `--data-dir`
  to find its on-disk material; backends should follow the same
  "one flag for backend selection + per-backend flags for the
  rest" shape.

## Open questions

- Multi-backend deployments (one backend for X.509, another for
  JWT) are not supported. The Authority interface returns one
  CA-cert PEM and one JWT-bundle JWKS; splitting them would
  require an interface revision.
- Hot reload of a backend (e.g. rotate KMS keys without
  restarting omega-server) is not in the interface. A future
  ADR may add it once a backend with online rotation lands.
