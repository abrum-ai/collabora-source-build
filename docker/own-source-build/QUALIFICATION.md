# Qualify and distribute an existing source-built image

This route reuses the successful source build. It never recompiles the rendering
engine to collect sources or to publish the same image. All workflows are manual,
public-repository-only and use free native standard runners. There are no Actions
cache/artifact uploads, larger runners or product deployments.

Run the generic local regression suite with `python3 test-source-closure.py`.
It uses synthetic OCI/archive/API fixtures and requires no registry credentials.

## 1. Bind the existing successful producer

Run `source-qualification.yml` with the actual successful source-build run ID,
its full Git commit, architecture and exact private runtime/source-evidence
digests. These are measured outputs, not values copied from a build plan.

The collector checks the original same-repository successful manual run, build
commit, private package ID/repository binding, matching version tags and digests.
The recipe files inside the source evidence must match the producing Git commit.
It reads the OCI blobs with its own scoped `GITHUB_TOKEN`, verifies descriptor
hashes/platforms, and inventories **every delivered layer**, including old APK
versions in overwritten base layers. Font directories and actual engine SPDX
packages become required review components. Nothing is extracted as a symlink,
device or escaping host path.

For every observed Alpine origin/commit, `fetch-apk-sources.sh` fetches exactly
that aports commit and preserves its APKBUILD/patches/install scripts. Official
`abuild validate fetch srcpkg` runs in a separate unprivileged disposable
container, without the host HOME, registry auth, GitHub token or Docker socket.
The produced package list must include each observed exact package/version.
The source package includes the checksum-verified upstream sources and local
patches. Missing metadata, unavailable sources or an unmatched version stop.
This process executes no engine build.

The resulting full source-closure **candidate remains private** in the original
private package. Its digest and inventory/checksum hashes are printed in the
job log/summary. The unresolved `review-required.json` is not a license clearance.

## 2. Perform the actual independent review

Read the runtime layer/APK inventory, engine SPDX components, fonts, collected
source archives and original licenses. Check every shipped component's actual
terms, source/build/installation requirements, notices and any relinking or
modification obligations. Do not infer completeness from an SPDX identifier,
an upstream URL, the existence of a source tarball or a boolean flag.

Complete a generic `reviews/*.json` document derived from `review-required.json`.
Bind the exact private closure digest, runtime/source digests and inventory
hashes. Every required component needs a resolved license decision, real source
archive hashes and original notice bytes with hashes. APK components require
their exact collected origin/commit source archive. Engine components require
both the pinned monorepo and actually downloaded engine external sources.
Notices can reference `archive::member::nested-member`; bytes are read without
extracting an arbitrary source tree. Preserve all applicable license texts.

Record the independent reviewer and a concrete review reference. The validator
checks mechanical byte/coverage bindings; it does **not** independently establish
that a review happened or that the legal decisions are correct. The maintainer
must verify that separate review before committing the completed manifest and
dispatching publication. An unresolved template, missing component, changed
artifact or absent source/notice cannot pass the mechanical gate.

Commit only generic source/license review data. No private integration sources,
customer data, credentials or private operational references belong here.

## 3. Prepare two separate public targets, with metadata only

`source-public-seeds.yml` creates only these new target names:

- `<build-repository>-runtime-public`
- `<build-repository>-sources-public`

It requires an actual package 404 before creating a seed. Authentication errors
or an existing package never trigger an overwrite/retry. The seed is generated
as an OCI layout with one layer containing exactly `LICENSE` and
`build-inputs.json`; it has no runtime/base ancestor or binary content. It is
downloaded again and all its blob/file hashes and two-file boundary are checked.
The job reports the actual private package IDs, repository binding, seed digest
and content proof. The existing private pilot is never made public.

An authorized package administrator then configures only these fresh verified
license-only targets as public using the documented GitHub Package settings.
GitHub's REST package API provides reads, deletion and restoration, not a
documented visibility mutation. The workflows do not invent an API endpoint or
change visibility. Repository access inheritance does not imply public package
visibility. Public visibility cannot subsequently be made private again.

## 4. Publish sources first, then prove anonymous runtime download

After the actual independent review, run `source-distribution.yml` from the
default branch with the exact producer inputs, private closure digest, committed
review path/SHA256 and actual IDs of the two separately public targets.

The workflow freshly rebinds the producer, private pilot and public target IDs,
downloads the existing closure, validates the completed review against all
actual source/notice bytes, and packages the reviewed sources/notices. This is
scratch packaging only. It publishes the complete sources first and downloads
all their OCI blobs with explicit **no credentials**, validating the full review
again against those downloaded bytes. Only then can it copy the original exact
runtime digest to the separate public target. No engine is rebuilt.

Existing immutable tags may only match the exact expected digest; different
content is never overwritten. Unknown writes require state inspection before
any manual recovery. After publication all runtime blobs are downloaded without
credentials, their digests/config/platform/build labels checked, and target IDs
and visibility read back again. The public product reference is the measured
`ghcr.io/<owner>/<repository>-runtime-public@sha256:...`, accompanied by the
measured complete sources/notices reference and review SHA256. Products need no
embedded team/customer PAT. First-use download and runtime caching are product
integration responsibilities. An anonymous CI pull does not qualify a real
document session, saving/reopening, VM resources or document isolation.

Primary references:

- [GHCR authentication, initial privacy and anonymous public pulls](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry)
- [Package permissions versus visibility; documented settings](https://docs.github.com/en/packages/learn-github-packages/configuring-a-packages-access-control-and-visibility)
- [REST package endpoints](https://docs.github.com/en/rest/packages/packages)
- [Alpine APKBUILD source/patch/checksum declarations](https://wiki.alpinelinux.org/wiki/APKBUILD_Reference)
- [Official abuild implementation](https://gitlab.alpinelinux.org/alpine/abuild)
- [MPL executable/source distribution](https://www.mozilla.org/en-US/MPL/2.0/#distribution-of-executable-form)
- [GPLv2 complete corresponding source](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html)
- [LGPLv3 combined-work obligations](https://www.gnu.org/licenses/lgpl-3.0.html)
