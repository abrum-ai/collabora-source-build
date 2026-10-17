#!/bin/sh
# Derived from Collabora Online docker/from-source/build-alpine.sh, MPL-2.0.
# Original copyright/license notices remain in the archived upstream sources.
set -eu
test "$UPSTREAM_COMMIT" = 28a3cf1a0edd6712e4079fdad8e46f5cbe6b8af8
test "$(id -u)" != 0
umask 022
# BEGIN PINNED SOURCE FUNCTIONS
# The original MPL-2.0 notices in this modified upstream file remain unchanged.
apply_engine_source_fix() {
    test "$(sha256sum engine/RepositoryExternal.mk | cut -d ' ' -f1)" = baeae35034eaa188ee73819ad45327c345e3fd08c6426b273d5597191d6cc6c6
    git apply --index <<'ARGON2_PATCH'
--- a/engine/RepositoryExternal.mk
+++ b/engine/RepositoryExternal.mk
@@ -1511,5 +1511,6 @@
 ifeq ($(OS),WNT)
 $(call gb_LinkTarget_use_package,$(1),argon2)
 else
+$(call gb_LinkTarget_use_external_project,$(1),argon2)
 $(call gb_Helper_LinkTarget_use_external,$(1),argon2)
 endif
ARGON2_PATCH
    test "$(sha256sum engine/RepositoryExternal.mk | cut -d ' ' -f1)" = 127e9cf7c8a46311650887128abfe9765d6c6db46fed9e20aae213d119f78de7
    test "$(git diff --cached --name-only)" = engine/RepositoryExternal.mk
}

archive_source_inputs() {
    offer=$1
    tarballs=$2
    argon2_license=$3
    # Refuse source changes not represented by the staged, reviewed patch.
    git diff --exit-code
    test "$(git diff --cached --name-only)" = engine/RepositoryExternal.mk
    test "$(sha256sum engine/RepositoryExternal.mk | cut -d ' ' -f1)" = 127e9cf7c8a46311650887128abfe9765d6c6db46fed9e20aae213d119f78de7
    test "$(sha256sum "$tarballs/phc-winner-argon2-20190702.tar.gz" | cut -d ' ' -f1)" = daf972a89577f8772602bf2eb38b6a3dd3d922bf5724d45e7f9589b5e830442c
    test "$(sha256sum "$argon2_license" | cut -d ' ' -f1)" = 220f8736a89ff51c92ef3d497f413b48e6cf1df3d6278bc909c6308c78e1718e
    cp "$argon2_license" "$offer/notices/argon2-LICENSE"
    git diff --cached --binary HEAD > "$offer/upstream-changes.patch"
    source_tree=$(git write-tree)
    # HEAD would omit our fix. Archive the exact staged source tree instead.
    # The fixed mtime avoids the current-time default for a tree object.
    bash -o pipefail -c 'git -c tar.umask=0022 archive --format=tar --mtime="@$1" "$2" | zstd -T1 -o "$3/online-source.tar.zst"' \
        source-archive "$SOURCE_DATE_EPOCH" "$source_tree" "$offer"
    python3 - "$offer" "$source_tree" <<'SOURCE_MANIFEST'
import hashlib, json, pathlib, subprocess, sys
offer, tree = pathlib.Path(sys.argv[1]), sys.argv[2]
def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(chunk)
    return value.hexdigest()
manifest = {
    'schema': 'source-modifications/1',
    'base_upstream_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
    'modified_source_tree': tree,
    'patch': {'path': 'upstream-changes.patch', 'sha256': digest(offer / 'upstream-changes.patch'), 'license': 'MPL-2.0'},
    'modified_files': [{'path': 'engine/RepositoryExternal.mk',
        'original_sha256': 'baeae35034eaa188ee73819ad45327c345e3fd08c6426b273d5597191d6cc6c6',
        'modified_sha256': digest(pathlib.Path('engine/RepositoryExternal.mk'))}],
    'source_archive': {'path': 'online-source.tar.zst', 'sha256': digest(offer / 'online-source.tar.zst'),
        'contains_applied_modification': True},
    'bundled_argon2': {
        'source_reference': 'engine-external-sources.tar.zst::tarballs/phc-winner-argon2-20190702.tar.gz',
        'original_archive_sha256': 'daf972a89577f8772602bf2eb38b6a3dd3d922bf5724d45e7f9589b5e830442c',
        'license_expression': 'CC0-1.0 OR Apache-2.0',
        'original_notice': 'notices/argon2-LICENSE',
        'original_notice_sha256': digest(offer / 'notices/argon2-LICENSE'),
        'upstream_build_patches': 'online-source.tar.zst::engine/external/argon2/'},
    'complete_component_license_review': False,
}
(offer / 'source-modifications.json').write_text(json.dumps(manifest, sort_keys=True, indent=2) + '\n')
SOURCE_MANIFEST
}
# END PINNED SOURCE FUNCTIONS
git init online
git -C online remote add origin https://github.com/CollaboraOnline/online.mirror.git
git -C online fetch --depth=1 origin "$UPSTREAM_COMMIT"
git -C online checkout --detach FETCH_HEAD
test "$(git -C online rev-parse HEAD)" = "$UPSTREAM_COMMIT"
test -z "$(git -C online status --porcelain)"
test -s online/engine/autogen.sh
test -s online/engine/download.lst
test -s online/browser/npm-shrinkwrap.json.in
cd online
apply_engine_source_fix
export SOURCE_DATE_EPOCH="$(git show -s --format=%ct HEAD)"
export MAKEFLAGS=-j1
mkdir -p /build/tarballs /build/instdir /build/offer/notices
cd /build/online/engine
./autogen.sh --with-distro=CPLinux-LOKit --without-package-format \
    --disable-symbols --without-java --with-lang=en-US \
    --without-system-argon2 --with-parallelism=1 --with-external-tar=/build/tarballs
make -j1
mkdir -p /build/instdir/opt
cp -a instdir /build/instdir/opt/collaboraoffice
cd /build/online
./autogen.sh
./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var \
    --disable-tests --with-lokit-path=/build/online/engine/include \
    --with-lo-path=/opt/collaboraoffice
make -j1
make -j1 collabora-online-sbom.spdx.json
DESTDIR=/build/instdir make install
cp COPYING /build/offer/notices/online-COPYING
cp engine/COPYING.MPL engine/COPYING.LGPL /build/offer/notices/
cp collabora-online-sbom.spdx.json /build/offer/notices/
cp /usr/local/bin/build-source /build/offer/build-source.sh
cp /source-recipe/Dockerfile /source-recipe/upstream.lock.json /build/offer/
cp engine/download.lst browser/npm-shrinkwrap.json.in /build/offer/notices/
cp config.log /build/offer/online-config.log
cp engine/config.log /build/offer/engine-config.log
archive_source_inputs /build/offer /build/tarballs /build/online/engine/workdir/UnpackedTarball/argon2/LICENSE
tar -C /build -cf - tarballs | zstd -T1 -o /build/offer/engine-external-sources.tar.zst
apk info -v > /build/offer/notices/build-apk-versions.txt
apk info -a > /build/offer/notices/build-apk-metadata.txt
printf '%s\n' '{"schema":"source-evidence-status/1","public_binary_distribution":"blocked","complete_corresponding_source_verified":false,"remaining":["exact runtime/base APK inventory and corresponding sources","complete component-license and source closure bound to the image digest"]}' > /build/offer/source-closure-status.json
printf '%s\n' "$UPSTREAM_COMMIT" > /build/offer/notices/upstream-commit.txt
cd /build/offer
find . -type f ! -name SHA256SUMS -exec sha256sum '{}' \; | sort > SHA256SUMS
