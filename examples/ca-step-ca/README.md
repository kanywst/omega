# examples/ca-step-ca

End-to-end demo of `omega server --ca-backend=step-ca`: prove that
omega delegates X.509-SVID signing to an upstream Smallstep step-ca
instance via the same `Authority` plugin seam (ADR 0005) that the
Vault PKI backend uses, with a real one-time-token (OTT) round-trip
on the wire.

`make demo` does six things:

1. mints a fresh ECDSA provisioner keypair via a tiny inline
   `keygen.go` (private JWK for omega, public JWK for the mock —
   nothing persists past `make down`);
2. boots a small `cmd/mock-step-ca` Go binary that stands up its
   own ECDSA Root CA and serves the two endpoints omega actually
   calls — `GET /roots.pem` and `POST /1.0/sign` — verifying the
   OTT signature against the provisioner public JWK on every sign;
3. boots `omega server` with `--ca-backend=step-ca` pointing at the
   mock, with the provisioner private JWK on the `--ca-step-ca-...`
   flags;
4. fetches `/v1/bundle` from omega and asserts the bundle subject is
   `CN=Mock step-ca Root CA` (not omega's local self-signed CA);
5. registers a SPIFFE namespace and submits a workload CSR via
   `POST /v1/svid`;
6. asserts the issued leaf chains to the bundle (`openssl verify`),
   carries the requested SPIFFE ID as a URI SAN, and is issued by
   the mock step-ca CA (so an accidental fall-back to omega's local
   self-signed default would fail the demo).

The OTT verification on the mock side keeps the demo honest: a
regression that breaks omega's OTT signing (wrong `iss`, missing
`sha` pin, stale `exp`, bad signature) gets a `401` and the demo
fails loudly instead of silently working against a permissive mock.

The mock is intentionally tiny — no `/1.0/health`, no provisioner
discovery, no order or ACME endpoints. A real deployment replaces
the mock by pointing `--ca-step-ca-url` at a live step-ca instance
and re-using the same provisioner private JWK that step-ca's
`ca.json` already has the matching public side for.

## Run

```text
make demo
```

The script tears itself down on exit; force a manual cleanup:

```text
make down
```

## Adapt to a real step-ca

Bring up step-ca (dev mode is fine for trying it out, but the demo
runs against the mock so CI does not depend on the step-ca image):

```text
step ca init \
  --name=Omega-Demo --dns=ca.example --address=:9000 \
  --provisioner=omega --provisioner-password-file=/tmp/pwd
step ca provisioner add omega --type=JWK --create
# step writes the matching public JWK into ca.json; export the
# private side (decrypted) into the file omega will load.
```

Then run omega against it:

```text
omega server \
  --trust-domain omega.example \
  --ca-backend step-ca \
  --ca-step-ca-url https://ca.example:9000 \
  --ca-step-ca-provisioner omega \
  --ca-step-ca-provisioner-key-file /run/secrets/omega-step-ca.jwk \
  --ca-step-ca-ca-cert /etc/ssl/step-ca-root.pem
```

`--ca-step-ca-provisioner-key-file` is the private JWK; in
production it is mounted from a secret store (Kubernetes Secret,
Vault, SOPS-encrypted file). The matching public JWK lives in
step-ca's `ca.json` and is what step-ca uses to verify the OTT
signature on every `/1.0/sign` call.
