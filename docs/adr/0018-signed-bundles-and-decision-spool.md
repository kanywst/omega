# ADR 0018: Signed policy bundles and a decision spool

## Status

Accepted. Extends [ADR 0016](0016-local-policy-decisions.md).

## Context

ADR 0016 left two gaps in local decisions. The bundle's revision is a content hash, so it detects corruption but not a forged bundle: its integrity rested entirely on the TLS connection to the control plane. And decisions waited in memory until the next flush, so an agent killed or crashed in between had already answered them and lost their record, with no loss report.

## Decision

1. **Signed bundles.** With `--policy-bundle-signing-key` (an ECDSA P-256 key, the same on every replica) the control plane signs each bundle it serves: the signature covers the revision, which is itself a hash of the whole content, under a fixed prefix. An agent started with `--policy-bundle-key` checks the revision against the content and the signature against that key, and refuses an unsigned or wrongly signed bundle. Without the flags nothing changes.
2. **A decision spool.** With `--decision-spool FILE` the agent writes each decision to the file and syncs it before answering, so a decision that was answered is on disk. At start it requeues what the spool holds; after every flush it rewrites the spool with what is still pending. A torn last line, which is what a crash mid-write leaves, belongs to a decision that was never answered and is skipped. A write or sync failure answers an error instead of a decision.

## Consequences

Easier:

- A bundle's trust no longer rests on TLS alone: a node that holds the public key accepts policy only from the holder of the private key.
- With the spool, an agent crash loses no answered decision; they reach the audit chain after the restart.

Harder:

- The signing key is one more secret, shared by every replica, and rotating it means restarting the agents with the new public key.
- The spool costs one fsync per decision and serialises decisions on it. The spool file holds request contents on the node's disk.
- Loss reports for decisions the control plane rejected (ADR 0016) are still kept in memory only.

## Scope fit

Rule 2 in [design-philosophy.md](../design-philosophy.md): *"Is it a control-plane decision Omega owns?"*

Yes. Both close gaps in Omega's own local-decision path.
