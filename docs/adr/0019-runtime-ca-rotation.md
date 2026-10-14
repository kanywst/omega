# ADR 0019: Rotating the built-in CA at runtime

## Status

Accepted.

## Context

With `--ca-backend=disk` Omega is its own issuer: one self-signed CA in `<data-dir>/ca` signs every X.509-SVID and JWT-SVID. Replacing that CA meant stopping the server, swapping the files and restarting, and every workload and federated peer trusting the old CA alone would reject everything the new one signed until it fetched the new bundle. A suspected key compromise had no clean answer, and `spiffe_sequence` stayed at 1 for the life of the process. The consuming side already rotates without a restart (ADRs 0009 and 0010); the issuing side did not.

## Decision

1. **Three CAs at most.** The CA directory holds the active CA (`ca.key`, `ca.crt`), optionally a prepared one (`ca.next.key`, `ca.next.crt`) and optionally the one it replaced (`ca.prev.crt`, certificate only). The trust bundle and the JWKS contain all of them; only the active one signs.
2. **Three steps, each picked up on `SIGHUP`.** `omega ca prepare` generates the next CA, which is then trusted but does not sign. `omega ca activate` makes it sign and keeps the old certificate as the previous CA. `omega ca retire` drops the previous CA, and refuses until 24 hours (the longest JWT-SVID lifetime) have passed since activation unless `--force`. The server re-reads the directory on `SIGHUP`, installs the new set atomically, keeps the old one on any error, republishes its federation bundle and advances `spiffe_sequence`.
3. **Overlap on both sides.** Because the next CA is trusted before it signs, and the previous one after it stops, peers and workloads that refresh their bundle between steps never see a certificate or token from a CA they do not trust. JWT-SVID validation picks the key by `kid` among the trusted CAs.
4. **Crash safety.** Each step writes through synced temporary files and renames. Activation keeps the old certificate first and moves the key before the certificate; a load that finds the new key next to the old certificate finishes the activation instead of failing.

## Consequences

Easier:

- The built-in CA can be replaced, routinely or after a suspected compromise, without a restart and without a window in which valid credentials are rejected.
- `spiffe_sequence` tells consumers when the bundle changed.

Harder:

- Each replica reads its own CA directory: an operator has to apply every step on all replicas, then signal them all, before moving to the next step.
- The steps are manual and depend on waiting long enough between them; Omega does not schedule rotations.
- Only `--ca-backend=disk` rotates this way. Vault PKI and step-ca rotate in their own systems; Omega keeps a CA they stop publishing in its served bundle for `--upstream-ca-grace`, 24 hours by default (never past the CA's expiry), records each change to that kept set in the audit chain as `ca.upstream`, drops a kept CA listed in `--upstream-ca-distrust` on `SIGHUP` after a compromise, and advances `spiffe_sequence`, so their rotations get the same overlap.

## Scope fit

Rule 2 in [design-philosophy.md](../design-philosophy.md): *"Is it a control-plane decision Omega owns?"*

Yes. When Omega is the issuer, the lifecycle of its signing key is Omega's to manage.
