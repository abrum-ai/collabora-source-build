# Collabora Online source-build candidate

This payload contains generic build files only. It builds the complete
Collabora Online monorepo at `28a3cf1a0edd6712e4079fdad8e46f5cbe6b8af8`:
the rendering engine, native server/kit and browser. It does not consume a CODE
vendor binary. The Alpine base index is fixed by digest. Engine external
downloads use upstream `engine/download.lst`; the browser uses upstream's
shrinkwrap and vendored `node_shrinkpack` with offline npm installation.

`build-source.sh` follows upstream `docker/from-source/build-alpine.sh`, with a
detached full-commit fetch and one compilation job. It is subject to MPL-2.0;
see `LICENSE`. Copyright and license notices in upstream sources are retained.
The engine also carries its original MPL/LGPL and third-party notices.

The candidate workflow is manual and restricted to a public repository and the
standard native `ubuntu-24.04` / `ubuntu-24.04-arm` runners. ARM64 is the default;
AMD64 requires a prior successful ARM64 run at the same build revision. It has no private
repository checkout, cloud deployment, paid runner or Actions cache/artifact
storage (including the Buildx setup action's binary cache). Buildx is fixed at
v0.38.0 and BuildKit v0.32.2 is fixed by image digest. It builds collected source
evidence and an SBOM, starts the runtime under cap-drop ALL / no-new-privileges /
read-only root, and checks Discovery. By default nothing is pushed. Optional
`stage_private` is for an internal pilot only; there is no public runtime
publication path. A staging tag is not an exception to source obligations.

If authenticated package metadata returns 404, only the `staging-bootstrap`
scratch target may be pushed once: it contains LICENSE and build-inputs.json,
no runtime/base layers or binaries. GitHub documents initial GHCR packages as
private, but the workflow does not infer admission from that default. It reads
the actual package back and verifies private visibility, exact owner/name and
linked build repository. Public, inaccessible, changed or unlinked metadata
stops before any runtime push. Private identity is checked freshly before each
binary/source-evidence push and again afterwards. The workflow never changes
visibility. Existing packages skip the bootstrap; failed/uncertain seed pushes
stop without an automatic write retry. Package access/repository settings may
still need normal administrative setup after a failed readback.

Private staging does not approve distribution outside the organization. Public
or customer binary distribution remains blocked until the full corresponding
source and notices for every shipped component are verified and made available
to its recipients. No release or `latest` tag is moved. Artifact selection uses
the actual digest, not a mutable staging name.

The workflow checks actual RAM/disk before building. The selected 40-GiB free
disk guard is a conservative qualification budget, not a measured minimum for
this commit. GitHub documents only 14 GB SSD for standard runners; a runner
without sufficient actual free space stops before compilation. Removing the
stock runner's unused Android/.NET/GHC toolchains is confined to that disposable
GitHub runner. There is no larger-runner fallback.

No successful build or bit-for-bit reproducibility is claimed yet. APK repositories
remain signed but time-varying; an actual run records exact build/runtime package
versions and metadata. Freeze/recover their corresponding APKs and all required
source packages before claiming reproducibility or allowing any public/customer
binary distribution. `source-evidence` includes the pinned monorepo (including vendored browser
sources), downloaded engine external sources, configure logs, SBOM and checksums.
It is not a blanket claim that all Alpine/base-package source obligations are
already discharged. Its source-closure-status.json explicitly records that the
complete offer is still unverified. That package-source closure is a prerequisite
to the first public binary distribution, including a staging tag.

Building this image does not authorize any deployment. A deployment without
capabilities may select the upstream `security.capabilities=false` mode. Without
Landlock that omits internal document/kit filesystem isolation; it requires a
separately enforced single-document outer-container boundary and restricted
document storage broker. Discovery alone does not qualify document editing,
saving, DOCX/XLSX compatibility or isolation between documents.

Primary sources:

- [Pinned Alpine source builder](https://github.com/CollaboraOnline/online.mirror/blob/28a3cf1a0edd6712e4079fdad8e46f5cbe6b8af8/docker/from-source/build-alpine.sh)
- [Pinned isolation configuration](https://github.com/CollaboraOnline/online.mirror/blob/28a3cf1a0edd6712e4079fdad8e46f5cbe6b8af8/coolwsd.xml.in)
- [GitHub standard runner resources](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
- [GitHub Packages billing](https://docs.github.com/en/billing/concepts/product-billing/github-packages)
- [GHCR initial visibility and repository binding](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry)
- [Mozilla MPL distribution FAQ](https://www.mozilla.org/en-US/MPL/2.0/FAQ/)
- [MPL 2.0, executable distribution section 3.2](https://www.mozilla.org/en-US/MPL/2.0/#distribution-of-executable-form)
