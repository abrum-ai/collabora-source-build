#!/bin/sh
# Derived from Collabora Online docker/from-source/build-alpine.sh, MPL-2.0.
# Original copyright/license notices remain in the archived upstream sources.
set -eu
test "$UPSTREAM_COMMIT" = 28a3cf1a0edd6712e4079fdad8e46f5cbe6b8af8
test "$(id -u)" != 0
umask 022
git init online
git -C online remote add origin https://github.com/CollaboraOnline/online.mirror.git
git -C online fetch --depth=1 origin "$UPSTREAM_COMMIT"
git -C online checkout --detach FETCH_HEAD
test "$(git -C online rev-parse HEAD)" = "$UPSTREAM_COMMIT"
test -z "$(git -C online status --porcelain)"
test -s online/engine/autogen.sh
test -s online/engine/download.lst
test -s online/browser/npm-shrinkwrap.json.in
export SOURCE_DATE_EPOCH="$(git -C online show -s --format=%ct HEAD)"
export MAKEFLAGS=-j1
mkdir -p /build/tarballs /build/instdir /build/offer/notices
cd /build/online/engine
./autogen.sh --with-distro=CPLinux-LOKit --without-package-format \
    --disable-symbols --without-java --with-lang=en-US \
    --with-parallelism=1 --with-external-tar=/build/tarballs
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
git archive --format=tar HEAD | zstd -T1 -o /build/offer/online-source.tar.zst
tar -C /build -cf - tarballs | zstd -T1 -o /build/offer/engine-external-sources.tar.zst
apk info -v > /build/offer/notices/build-apk-versions.txt
apk info -a > /build/offer/notices/build-apk-metadata.txt
printf '%s\n' '{"schema":"source-evidence-status/1","public_binary_distribution":"blocked","complete_corresponding_source_verified":false,"remaining":["exact runtime/base APK inventory and corresponding sources","complete component-license and source closure bound to the image digest"]}' > /build/offer/source-closure-status.json
printf '%s\n' "$UPSTREAM_COMMIT" > /build/offer/notices/upstream-commit.txt
cd /build/offer
find . -type f ! -name SHA256SUMS -exec sha256sum '{}' \; | sort > SHA256SUMS
