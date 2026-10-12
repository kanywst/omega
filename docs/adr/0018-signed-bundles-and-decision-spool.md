# ADR 0018: Signed policy bundles and a decision spool

## Status

Accepted. Extends [ADR 0016](0016-local-policy-decisions.md).

## Context

ADR 0016 left two gaps in local decisions. The bundle's revision is a content hash, so it detects corruption but not a forged bundle: its integrity rested entirely on the TLS connection to the control plane. And decisions waited in memory until the next flush, so an agent killed or crashed in between had already answered them and lost their record, with no loss report.

## Decision

1. **Signed bundles.** With `--policy-bundle-signing-key` (an ECDSA P-256 key, the same on every replica) the control plane signs each bundle it serves: the signature covers the revision, which is itself a hash of the whole content, and the time it was served, under a fixed prefix. An agent started with `--policy-bundle-key` checks the revision against the content and the signature against that key, and refuses an unsigned or wrongly signed bundle. To stop a valid old bundle being replayed, it also refuses one issued before the newest it has loaded (kept next to the spool, so a restart remembers it), longer ago than `--policy-max-age`, or more than a minute in the future. With a key configured the agent never asks for a `304`, which carries no signature: every refresh is a signed bundle, so the freshness checks run on every sync. Without the flags nothing changes.
2. **A decision spool.** With `--decision-spool FILE` the agent writes each decision to the file and syncs it before answering, so a decision that was answered is on disk. At start it requeues what the spool holds; after every flush it rewrites the spool with what is still pending. A torn last line, which is what a crash mid-write leaves, belongs to a decision that was never answered and is skipped; an unreadable line anywhere else is an answered decision, so the agent refuses to start rather than lose it. A write or sync failure answers an error instead of a decision and cuts the file back to where that write began, so no byte of an unanswered decision stays to merge with the next line or be requeued.

## Consequences

Easier:

- A bundle's trust no longer rests on TLS alone: a node that holds the public key accepts policy only from the holder of the private key.
- With the spool, an agent crash loses no answered decision; they reach the audit chain after the restart.

Harder:

- The signing key is one more secret, shared by every replica, and rotating it means restarting the agents with the new public key. Agents and the control plane need roughly synchronised clocks for the issue-time check.
- With a signing key every sync downloads the whole bundle. Replicas stamp `issued_at` with their own clocks, so replicas whose clocks differ can make a lagging one's bundles look older than one already loaded, which shows as failed syncs; keep the control plane's clocks synchronised. Without the spool the newest issue time is kept in memory only.
- Delivery from the spool is at least once: an agent that crashes after a batch was recorded but before the spool was rewritten sends it again, so the chain can hold a decision twice; count by `decision_id`.
- The spool costs one fsync per decision and serialises decisions on it. The spool file holds request contents on the node's disk.
- Loss reports for decisions the control plane rejected (ADR 0016) are still kept in memory only.

## Scope fit

Rule 2 in [design-philosophy.md](../design-philosophy.md): *"Is it a control-plane decision Omega owns?"*

Yes. Both close gaps in Omega's own local-decision path.
