# Releasing Omega

This page describes how a maintainer cuts a release. Releases are
cut from `main` only.

## Versioning

- [Semantic Versioning 2.0.0](https://semver.org/).
- Pre-1.0 (current phase): minor bumps may include breaking changes.
  Patch bumps remain backward compatible.
- Tag format: `vX.Y.Z` (e.g. `v0.1.0`). The `chart-releaser` action
  also produces an `omega-X.Y.Z` Helm chart tag automatically; do not
  create that one by hand.

## Cadence

Pre-1.0: release as features are ready, with at most one minor per
month so downstream consumers can plan upgrades.

After 1.0: minor releases on a 6-week cadence, patch releases as
needed.

## Pre-release checklist

1. CI on `main` is green for the release commit (test, cross, demo,
   examples, helm, kind-operator, govulncheck, gosec, markdownlint).
2. `CHANGELOG.md` `[Unreleased]` section is populated. In the release
   commit, rename it to the new version heading and add a fresh empty
   `[Unreleased]` block.
3. `make demo` and `make docker-demo` pass on the release commit
   locally.
4. `charts/omega/Chart.yaml` `version` and `appVersion` are bumped to
   the new version (chart-releaser uses `version` as the source of
   truth).
5. README quickstart still works against the new image tag.

## Cutting the release

```text
git switch main && git pull --ff-only
git tag -a vX.Y.Z -m "Omega vX.Y.Z"
git push origin vX.Y.Z
```

The `vX.Y.Z` tag triggers two jobs in
[`.github/workflows/ci.yml`](.github/workflows/ci.yml):

1. `image`: builds linux/amd64 + linux/arm64, pushes to
   `ghcr.io/kanywst/omega:X.Y.Z` and the `:X.Y` and `:X.Y.Z-<sha>`
   floating tags.
2. `chart-release`: packages `charts/omega`, appends to
   `gh-pages/index.yaml`, and publishes the chart at
   `https://kanywst.github.io/omega/`.

Do not hand-edit the `gh-pages` branch (see
[CLAUDE.md](CLAUDE.md) note in the repo). The only manual touch was
the bootstrap orphan commit.

## Post-release verification

- `helm repo update && helm search repo omega` shows the new version.
- The Helm chart `.tgz` was cosign-signed and its sigstore bundle is
  attached to the `omega-X.Y.Z` GitHub Release. Verify with:

  ```text
  helm pull omega/omega --version X.Y.Z
  gh release download omega-X.Y.Z \
    --repo kanywst/omega \
    --pattern 'omega-X.Y.Z.tgz.sigstore.json'
  cosign verify-blob \
    --bundle omega-X.Y.Z.tgz.sigstore.json \
    --certificate-identity-regexp '^https://github\.com/kanywst/omega/\.github/workflows/ci\.yml@refs/tags/v' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    omega-X.Y.Z.tgz
  ```

- Both architectures pull cleanly. `docker pull` defaults to the
  host's platform, so verify each explicitly:

  ```text
  docker pull --platform linux/amd64 ghcr.io/kanywst/omega:X.Y.Z
  docker pull --platform linux/arm64 ghcr.io/kanywst/omega:X.Y.Z
  ```

- The image's keyless cosign signature verifies against the
  workflow that produced it:

  ```text
  cosign verify ghcr.io/kanywst/omega:X.Y.Z \
    --certificate-identity-regexp '^https://github\.com/kanywst/omega/\.github/workflows/ci\.yml@refs/tags/v' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com
  ```

- A per-platform SPDX SBOM is attached to each architecture's
  manifest as a cosign attestation. The SBOM hangs off the per-arch
  manifest, not the index, so resolve that digest first and verify it
  directly — `cosign verify-attestation` has no `--platform` flag:

  There is one SBOM per architecture, so this runs **twice** — once
  per digest. Verifying only one arch leaves the other unchecked:

  ```text
  AMD=$(crane digest --platform linux/amd64 ghcr.io/kanywst/omega:X.Y.Z)
  ARM=$(crane digest --platform linux/arm64 ghcr.io/kanywst/omega:X.Y.Z)

  for DIGEST in "$AMD" "$ARM"; do
    cosign verify-attestation \
      --type spdxjson \
      --certificate-identity-regexp '^https://github\.com/kanywst/omega/\.github/workflows/ci\.yml@refs/tags/v' \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com \
      "ghcr.io/kanywst/omega@$DIGEST"
  done
  ```

  Without `crane`, read the digests straight out of the index:

  ```text
  TOKEN=$(curl -s 'https://ghcr.io/token?scope=repository:kanywst/omega:pull&service=ghcr.io' \
    | python3 -c 'import sys,json; print(json.load(sys.stdin)["token"])')
  curl -s https://ghcr.io/v2/kanywst/omega/manifests/X.Y.Z \
    -H "Authorization: Bearer $TOKEN" \
    -H 'Accept: application/vnd.oci.image.index.v1+json' \
    | python3 -c 'import sys,json
  for m in json.load(sys.stdin)["manifests"]:
      p = m.get("platform", {})
      if p.get("os") == "linux": print(p["architecture"], m["digest"])'
  ```

  The amd64 SBOM is also published as a build artefact named
  `omega-sbom-linux-amd64.spdx.json`; arm64 likewise.

- The SLSA Build Level 3 provenance attestation is reachable through
  `gh`. The flag is `--signer-workflow` and it takes the full
  `owner/repo/path` form; a bare `--workflow ci.yml` is not a `gh
  attestation verify` flag:

  Verify the **index digest**, not the tag. The attestation subject is
  `steps.build.outputs.digest`, which at tag time is the multi-arch
  index; a tag is a mutable ref, so pinning the digest is what actually
  ties the provenance to the artefact you shipped:

  ```text
  INDEX=$(crane digest ghcr.io/kanywst/omega:X.Y.Z)   # index, not per-arch

  gh auth status                                      # preflight
  gh attestation verify "oci://ghcr.io/kanywst/omega@$INDEX" \
    --repo kanywst/omega \
    --signer-workflow kanywst/omega/.github/workflows/ci.yml
  ```

  Without `crane`, the index digest is the `Docker-Content-Digest`
  header on a HEAD of the manifest, requested with the index media
  type. The `Accept` header is required, not decorative: without it
  GHCR answers `404 MANIFEST_UNKNOWN` — *"OCI index found, but Accept
  header does not support OCI indexes"* — which looks like a missing
  image rather than a malformed request:

  ```text
  curl -sI https://ghcr.io/v2/kanywst/omega/manifests/X.Y.Z \
    -H "Authorization: Bearer $TOKEN" \
    -H 'Accept: application/vnd.oci.image.index.v1+json' \
    | grep -i docker-content-digest
  ```

  Two access notes. This command reads GitHub's attestation store,
  which is **not** the registry: the token `gh` uses is not the one
  that authenticated the `docker` / `cosign` pulls above, so registry
  access alone is not enough. It needs a classic PAT with
  `read:packages`, or a fine-grained token with `attestations:read`.
  Without it the command fails with "the provided token was denied
  access", which reads like a missing attestation rather than a local
  credential gap. Separately, GHCR's referrers API does not enumerate
  these attestations, so an empty referrers list is not evidence that
  provenance is missing either.

- A draft GitHub Release with the relevant `CHANGELOG.md` excerpt is
  prepared and reviewed by another maintainer before publishing.

## Hotfix process

For a security or critical-bug fix on the latest minor:

1. Branch `release/X.Y` from the prior tag if it does not already
   exist.
2. Cherry-pick the fix and bump to `vX.Y.(Z+1)`.
3. Tag and push as in "Cutting the release". Backport to `main`
   separately.

## Yanking a release

Releases are not deleted from GHCR or the Helm index. To yank a broken
release, publish a `vX.Y.(Z+1)` immediately and update the affected
versions list in [`SECURITY.md`](SECURITY.md), plus a "yanked" note
in [`CHANGELOG.md`](CHANGELOG.md).
