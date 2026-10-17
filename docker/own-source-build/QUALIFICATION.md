# Qualify and distribute an existing source-built image

This route reuses the successful source build. It never recompiles the rendering
engine to collect sources or to publish the same image. All workflows are manual,
public-repository-only and use free native standard runners. There are no Actions
cache/artifact uploads, larger runners or product deployments.
Each workflow admits only the default-branch dispatch and checks that its local
checkout is the exact immutable `GITHUB_SHA` before running the regression suite
or accessing package credentials. This does not dispatch or approve a workflow.

Run the generic local regression suite with `python3 test-source-closure.py`.
It uses synthetic OCI/archive/API fixtures and requires no registry credentials.

## 1. Bind the existing successful producer

Run `source-qualification.yml` with operation `collect`, the actual successful source-build run ID,
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

The container's outputs remain untrusted on the host. Before reading or copying,
the collector rejects symlinked/escaping package lists, source archives and
archive directories. It verifies the exact package/version list and the source
package's single regular `APKBUILD` against the original pinned aports recipe.
A rewritten or duplicate recipe fails; only that verified archive, original
recipe and package list enter the new evidence directory, without replacing an
existing result. Source archives are inspected without unpacking an arbitrary
source tree on the host.

The resulting full source-closure **candidate remains private** in the original
private package. Its digest and inventory/checksum hashes are printed in the
job log/summary. The unresolved `review-required.json` is not a license clearance.

## 2. Perform the actual independent review

### Inspect the private candidate without a personal package token

Use operation `inspect` in the same workflow with the original producer inputs
and the **exact private closure digest** reported by collection. This is a
separate job with only `contents: read`, `actions: read`, and `packages: read`.
It uses the repository's workflow `GITHUB_TOKEN` to read its associated private
package; it never pushes an image, uploads an artifact/cache, changes visibility,
executes an engine or source recipe, or creates a review decision. The public
repository must actually retain Actions read access to the private package.
A 401/403 is a failed prerequisite, never a reason to introduce a team/customer
PAT or to publish an unreviewed runtime.

Both collector and reader admit only an exact default-branch checkout. The
reader freshly binds the successful original producer and package before the
pull and again before inspecting. It checks OCI descriptor/content/platform
hashes and compares the candidate's complete embedded build binding with that
fresh observation. The reader's own Run, Attempt, unique numeric Job ID, workflow
path and workflow commit are verified through the Actions API and bound into
the output, together with the actual helper hash.

An inventory-only inspection emits the full original build binding, runtime
layer inventory, components, APK origins/checksums, unresolved review template,
engine SPDX inventory, and a complete candidate file index with sizes and hashes.
To inspect actual notices, manifests or small archive bytes, commit a generic
`inspections/*.json` selection and pass its path as `selection_file`, for example:

```json
{
  "schema": "source-inspection-request/1",
  "closure_digest": "sha256:<exact-private-candidate-hash>",
  "references": [
    "source-evidence/online-source.tar.zst::@members",
    "source-evidence/engine-external-sources.tar.zst::@members"
  ]
}
```

The example digest is a placeholder. The request must contain the actual digest
and match its exact committed bytes. `::@members` produces a complete bounded
archive index with regular member hashes, sizes and types, so a reviewer can
discover exact notice paths without private registry access. A subsequent
selection can request `source-evidence/archive::actual/member/COPYING`, including
up to three nested archives, or a bounded whole source-evidence/APK file. Links
are inventoried without following them and cannot be read as regular notices.
Only candidate `source-evidence/` and `apk-sources/` paths are selectable; host
paths, symlink ancestors, traversal, ambiguous members and invalid/truncated
compression streams fail closed. ZIP CRCs and complete compression trailers
are checked. All TAR consumers share the same boundary, including OCI layer
inventory/extraction, APKBUILD selection, nested review notices and inspection.
The entire decoded TAR is first spooled to a temporary seekable data file, with
an 8 GiB limit. Before the first member is available, the reader verifies member
extents/padding and the logical first TAR end independently of parser read-ahead:
at least two zero end blocks, 512-byte alignment, at most 1 MiB zero-only final
padding, and no second archive or nonzero trailing data. Concatenated compression
frames are fully decoded and must together contain just that one valid TAR;
truncated/corrupt frames or ignored compressed garbage cannot pass. Metadata
headers are bounded before allocation, excessive nesting/counts and sparse TAR
formats fail closed. Ordinary POSIX/PAX/GNU archives and canonical zero padding
remain supported. ZIP readers require a ZIP header at the start; an appended ZIP
cannot disguise a nonzero TAR tail. This data spool is not an extracted directory tree and needs
up to the decoded budget in ephemeral disk in addition to the OCI download.
Archive data is never executed or unpacked as a host directory tree.

All output is validated before the first evidence record. Limits are 32 unique
selections, 4 MiB per selected file/final member or complete archive index,
16 MiB per intermediate archive/inventory, 8 GiB decompressed per archive,
100,000 index entries, 24 MiB total document bytes and a 32 KiB frame header.
An excessive request fails rather than emitting a truncated success; split
explicit selections across separate bound inspections if needed.

Raw job logs contain `SOURCE_INSPECTION_V1` JSON begin/chunk/complete records.
Document bytes are base64 encoded in 12 KiB chunks; references and metadata are
JSON escaped. Notices cannot inject Actions commands, terminal escapes or new
evidence records. The manifest binds every document's length, hash and chunk
count. Missing, reordered, duplicated or changed frames fail offline decoding.

Retrieve the **raw job log** through GitHub's documented job-log REST endpoint,
not a formatted CLI transcript. The public log is readable without a private
package credential. Independently verify the successful Run/Attempt, numeric Job
and workflow SHA through GitHub, preserve the raw log bytes/hash and those API
receipts in the review record, then decode locally with no registry/API access:

```sh
python3 qualify-source.py decode-inspection \
  --log-file saved-raw-job.log --run-id ACTUAL_RUN --run-attempt ACTUAL_ATTEMPT \
  --job-id ACTUAL_JOB --workflow-commit ACTUAL_WORKFLOW_COMMIT \
  --closure-digest sha256:ACTUAL_CANDIDATE_HASH --destination NEW_LOCAL_DIRECTORY
```

The destination contains `manifest.json` and numbered `.bin` documents; external
references never become host paths. Hashes/framing detect changed or incomplete
downloads; they are not a signature authenticating a log copied from elsewhere.
Use the actual trusted GitHub run/job and preserved raw receipts as provenance.
The complete marker proves only the requested inspection snapshot, never full
legal/source clearance or successful publication.

### Record the independent component decisions

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
An empty component inventory, unknown component kind or missing canonical APK/
engine source requirements also fails. Hashing a changed requirements list does
not reduce the source obligations that this version of the collector enforces.

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
The seed workflow has its own `source-public-package-metadata` concurrency group;
it can prepare these metadata targets without occupying or replacing the engine
build's pending slot. Read-only inspections also use a separate per-run group.
Collector and publisher retain `full-source-build`; dispatch them in sequence
after the preceding run has completed to preserve their single pending slot.
No additional engine build is needed for any of these operations.

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
- [Workflow token and package Actions access](https://docs.github.com/en/packages/learn-github-packages/about-permissions-for-github-packages)
- [Raw job logs and public read access](https://docs.github.com/en/rest/actions/workflow-jobs#download-job-logs-for-a-workflow-run)
- [Concurrency groups and pending queue behavior](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/control-workflow-concurrency)
- [Alpine APKBUILD source/patch/checksum declarations](https://wiki.alpinelinux.org/wiki/APKBUILD_Reference)
- [Official abuild implementation](https://gitlab.alpinelinux.org/alpine/abuild)
- [MPL executable/source distribution](https://www.mozilla.org/en-US/MPL/2.0/#distribution-of-executable-form)
- [GPLv2 complete corresponding source](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html)
- [LGPLv3 combined-work obligations](https://www.gnu.org/licenses/lgpl-3.0.html)
