# Implementing a CA backend

omega's `internal/server/identity/Authority` interface is the
Plugin-layer seam for CA backends. The default disk-backed
implementation ships in-tree; HSM, KMS, and external-CA backends
slot in here by satisfying the same interface. The architectural
contract behind this is [ADR 0005](adr/0005-ca-plugin-architecture.md);
this page is the step-by-step companion.

The audience is contributors writing a new in-tree backend (PR
against omega) or an out-of-tree backend (a separate Go module
that vendors the interface from omega and registers itself at
process start). The mechanics are the same; only the location of
the code differs.

## Step 1 — pick a Kind name

In [`internal/server/identity/authority.go`](../internal/server/identity/authority.go):

```go
type Kind string

const (
    KindDisk Kind = "disk"
    // ...your new constant here, e.g.:
    KindVaultPKI Kind = "vault-pki"
)
```

The string value is what operators will pass to the CLI flag that
selects backends. Stick to short, kebab-case identifiers.

## Step 2 — extend Config

`identity.Config` is the disjoint-union argument to `New`. Each
backend reads only the fields relevant to its Kind:

```go
type Config struct {
    Kind        Kind
    TrustDomain string
    Issuer      string

    // KindDisk
    Dir string

    // ...your fields, e.g.:
    VaultPKIAddr  string
    VaultPKIToken string
    VaultPKIRole  string
}
```

Required fields per backend are enforced inside `New` (see step 4).
The `TrustDomain` and `Issuer` fields are shared across every
backend and are validated by the top of `New` before the Kind
switch.

## Step 3 — implement the Authority interface

Create a new file `internal/server/identity/<backend>.go` with a
struct that satisfies the interface:

```go
type vaultPKIAuthority struct {
    trustDomain spiffeid.TrustDomain
    issuerURL   string
    client      *vault.Client
    bundlePEM   []byte
    jwtSigner   crypto.Signer
}

var _ Authority = (*vaultPKIAuthority)(nil)
```

The interface methods (recap):

| Method | Implementer must |
| --- | --- |
| `TrustDomain()` | Return the parsed `spiffeid.TrustDomain` |
| `BundlePEM()` | Return the trust-anchor PEM bytes |
| `IssueSVID(id, pub)` | Sign a 30-min X.509-SVID for `id` using the backend's CA |
| `IssueJWTSVID(id, aud, ttl, extra)` | Sign a JWT-SVID with `iss=IssuerURL()` when configured |
| `JWTKeyID()` | Return a stable key id derived from the signing public key |
| `JWTBundle()` | Return the JWKS that verifies the issued JWT-SVIDs |
| `IssuerURL()` | Return the OIDC issuer URL configured in `Config.Issuer`, or `""` |
| `ValidateJWTSVID(token, aud)` | Verify signature + standard time claims + audience |
| `ValidatePresentedCertBinding(token, aud, cert)` | Run `ValidateJWTSVID` plus the RFC 8705 `cnf.x5t#S256` check |
| `ParseJWTSVIDClaims(token)` | Verify signature + standard time claims, return raw claims |

The `localAuthority` struct in
[`internal/server/identity/authority.go`](../internal/server/identity/authority.go)
and [`internal/server/identity/jwt.go`](../internal/server/identity/jwt.go)
is the reference. It is short on purpose (≈ 250 lines for both
X.509 and JWT issuance); a remote-signer backend will be similar
in shape with the local `crypto.Signer` replaced by a
KMS-backed one.

## Step 4 — register in identity.New

Extend the `switch` in `identity.New`:

```go
switch cfg.Kind {
case "", KindDisk:
    // ...existing case...
case KindVaultPKI:
    if cfg.VaultPKIAddr == "" {
        return nil, errors.New("identity: vault-pki backend requires VaultPKIAddr")
    }
    a, err := newVaultPKIAuthority(td, cfg.VaultPKIAddr, cfg.VaultPKIToken, cfg.VaultPKIRole)
    if err != nil {
        return nil, err
    }
    a.issuerURL = issuer // the shared, validated issuer URL
    return a, nil
default:
    return nil, fmt.Errorf("identity: unknown kind %q", cfg.Kind)
}
```

Per-backend required-field validation lives in this case (not
inside the constructor) so misconfiguration fails at startup
with a clear message naming the offending Kind.

## Step 5 — CLI wiring

`internal/cli/server.go` already exposes the `--issuer-url`,
`--trust-domain`, and `--data-dir` flags shared across backends.
Add backend selection + per-backend flags:

```go
var caBackend string
cmd.Flags().StringVar(&caBackend, "ca-backend", "disk", "CA backend (disk|vault-pki|...)")

var vaultPKIAddr, vaultPKIToken, vaultPKIRole string
cmd.Flags().StringVar(&vaultPKIAddr,  "ca-vault-pki-addr",  "", "Vault PKI base URL (when --ca-backend=vault-pki)")
cmd.Flags().StringVar(&vaultPKIToken, "ca-vault-pki-token", "", "Vault token; prefer file://path or env: for production")
cmd.Flags().StringVar(&vaultPKIRole,  "ca-vault-pki-role",  "", "Vault PKI role")
```

In `RunE`, build the Config:

```go
caCfg := identity.Config{
    Kind:        identity.Kind(caBackend),
    TrustDomain: trustDomain,
    Issuer:      strings.TrimSpace(issuerURL),
    Dir:         filepath.Join(dataDir, "ca"),
}
if caBackend == string(identity.KindVaultPKI) {
    caCfg.VaultPKIAddr  = vaultPKIAddr
    caCfg.VaultPKIToken = vaultPKIToken
    caCfg.VaultPKIRole  = vaultPKIRole
}
ca, err := identity.New(caCfg)
```

## Step 6 — tests

Every in-tree backend gets a unit-test file
`internal/server/identity/<backend>_test.go` that exercises every
interface method. The disk backend's tests
([`authority_test.go`](../internal/server/identity/authority_test.go),
[`jwt_test.go`](../internal/server/identity/jwt_test.go))
are the reference shape.

For backends that require a real upstream (Vault, AWS KMS), the
tests live behind an env-var gate so default `go test` runs
without secrets and CI is wired to inject the secret only on the
backend's own job.

Pattern from the existing Postgres tests:

```go
func TestVaultPKIIssueRoundTrip(t *testing.T) {
    addr := os.Getenv("OMEGA_TEST_VAULT_PKI_ADDR")
    if addr == "" {
        t.Skip("OMEGA_TEST_VAULT_PKI_ADDR not set")
    }
    // ...exercise the backend...
}
```

## Step 7 — documentation

Three places need updating in the same PR:

1. `README.md` Standards-alignment table - mark the backend
   row, e.g. `HSM / KMS upstream | Vault PKI / step-ca / AWS PCA / GCP CAS / Azure KV | partial (vault-pki implemented)`.
2. `CHANGELOG.md` `[Unreleased]` - record the new flag set and
   the Kind constant.
3. `ROADMAP.md` "Later" - cross off this backend or move others
   to "Now"/"Next" depending on what is next.

## Out-of-tree plugins

Out-of-tree backends are supported through the same mechanism:

1. The third-party module imports
   `github.com/0-draft/omega/internal/server/identity` (this
   forces vendoring since it is `internal/`).
2. The third-party `main` constructs an `identity.Authority`
   directly and passes it into a forked `cmd/omega` entry point.

If you maintain a long-lived out-of-tree backend and want it
upstreamed, open a Discussion first. The bar is: real users, a
maintainer who can stay on top of interface drift, and a working
test harness.

## What this guide does not cover

- Key rotation between backends. The interface returns one
  bundle PEM; coordinated rotation between two backends is an
  operator workflow, not an interface concern.
- Online key rotation within a backend (rotate the upstream KMS
  key without restarting omega-server). Not currently in the
  interface; a future ADR may add a `Rotate(ctx)` hook once a
  backend that needs it lands.
- CRL / OCSP responder behaviour. omega's revocation model is
  short-lived SVIDs ([ADR 0003](adr/0003-short-lived-svids-no-revocation.md));
  no backend implements `Revoke`.
