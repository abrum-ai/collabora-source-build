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

apply_browser_source_fix() {
    test "$(sha256sum browser/css/qtapp-tabstrip.css | cut -d ' ' -f1)" = 01dd2b158aa38c2165b003cab20f667f0b8bf02e68e26cfde1107c431d332694 || return 1
    git apply --index <<'BROWSER_CSS_PATCH'
diff --git a/browser/css/qtapp-tabstrip.css b/browser/css/qtapp-tabstrip.css
index 0c05716..0540b80 100644
--- a/browser/css/qtapp-tabstrip.css
+++ b/browser/css/qtapp-tabstrip.css
@@ -89,37 +89,36 @@ body {
 	border-radius: 0;
 	background: var(--color-main-background);
 	--close-color: var(--color-main-background);
-	mask:
-		linear-gradient(#000 0 0) center bottom /
-			calc(100% - 2 * var(--tab-radius)) calc(100% - var(--tab-radius))
-			no-repeat,
+	mask: linear-gradient(#000 0 0) center bottom /
+		calc(100% - 2 * var(--tab-radius)) calc(100% - var(--tab-radius))
+		no-repeat,
 		linear-gradient(#000 0 0) center top / calc(100% - 4 * var(--tab-radius))
-			var(--tab-radius) no-repeat,
+		var(--tab-radius) no-repeat,
 		radial-gradient(
-				circle at 100% 100%,
-				#000 calc(var(--tab-radius) - 0.5px),
-				#0000 var(--tab-radius)
-			)
-			var(--tab-radius) 0 / var(--tab-radius) var(--tab-radius) no-repeat,
+			circle at 100% 100%,
+			#000 calc(var(--tab-radius) - 0.5px),
+			#0000 var(--tab-radius)
+		)
+		var(--tab-radius) 0 / var(--tab-radius) var(--tab-radius) no-repeat,
 		radial-gradient(
-				circle at 0 100%,
-				#000 calc(var(--tab-radius) - 0.5px),
-				#0000 var(--tab-radius)
-			)
-			right var(--tab-radius) top 0 / var(--tab-radius) var(--tab-radius)
-			no-repeat,
+			circle at 0 100%,
+			#000 calc(var(--tab-radius) - 0.5px),
+			#0000 var(--tab-radius)
+		)
+		right var(--tab-radius) top 0 / var(--tab-radius) var(--tab-radius)
+		no-repeat,
 		radial-gradient(
-				circle at 0 0,
-				#0000 calc(var(--tab-radius) - 0.5px),
-				#000 var(--tab-radius)
-			)
-			left bottom / var(--tab-radius) var(--tab-radius) no-repeat,
+			circle at 0 0,
+			#0000 calc(var(--tab-radius) - 0.5px),
+			#000 var(--tab-radius)
+		)
+		left bottom / var(--tab-radius) var(--tab-radius) no-repeat,
 		radial-gradient(
-				circle at 100% 0,
-				#0000 calc(var(--tab-radius) - 0.5px),
-				#000 var(--tab-radius)
-			)
-			right bottom / var(--tab-radius) var(--tab-radius) no-repeat;
+			circle at 100% 0,
+			#0000 calc(var(--tab-radius) - 0.5px),
+			#000 var(--tab-radius)
+		)
+		right bottom / var(--tab-radius) var(--tab-radius) no-repeat;
 }
 /* The visible edges of the active tab are one radius in from its box. */
 .tab.active .content {
BROWSER_CSS_PATCH
    test "$(sha256sum browser/css/qtapp-tabstrip.css | cut -d ' ' -f1)" = c8809ee6e43429c74272d0d3b59cfec7cb5d78d5899c87c1fb66ddcf7aa17953 || return 1
}

verify_source_inputs() (
    # The production engine make runs one directory below the Online root.
    # Keep this check independent of the caller's working directory.
    cd "$(git rev-parse --show-toplevel)" || return 1
    git diff --exit-code || return 1
    test "$(git diff --cached --name-only)" = "$(printf '%s\n' browser/css/qtapp-tabstrip.css engine/RepositoryExternal.mk)" || return 1
    test "$(sha256sum engine/RepositoryExternal.mk | cut -d ' ' -f1)" = 127e9cf7c8a46311650887128abfe9765d6c6db46fed9e20aae213d119f78de7 || return 1
    test "$(sha256sum browser/css/qtapp-tabstrip.css | cut -d ' ' -f1)" = c8809ee6e43429c74272d0d3b59cfec7cb5d78d5899c87c1fb66ddcf7aa17953 || return 1
)

preflight_browser_sources() {
    # Own fresh offline-install cache only; never remove an existing directory.
    test ! -e browser/.source-preflight-npm-cache && test ! -L browser/.source-preflight-npm-cache || return 1
    npm_config_cache="$(pwd)/browser/.source-preflight-npm-cache" make -j1 -C browser node_modules || return 1
    rm -rf -- browser/.source-preflight-npm-cache || return 1
    (cd browser && node node_modules/stylelint/bin/stylelint.js --config .stylelintrc.json css/*.css --fix) || return 1
    verify_source_inputs || return 1
}

archive_source_tree() {
    # Stream the REAL tree before heavy without retaining a second archive.
    # All pipelines are drained synchronously and every child status checked.
    python3 - "$1" "$2" "$3" "$SOURCE_DATE_EPOCH" <<'SOURCE_ARCHIVE'
import hashlib, json, pathlib, stat, subprocess, sys
mode, offer, tree, epoch = sys.argv[1], pathlib.Path(sys.argv[2]), sys.argv[3], sys.argv[4]
def measured(commands, destination=None):
    children = []; previous = None; output = None
    try:
        if destination is not None: output = destination.open('xb')
        for command in commands:
            child = subprocess.Popen(command, stdin=previous, stdout=subprocess.PIPE)
            if previous is not None: previous.close()
            children.append(child); previous = child.stdout
        value = hashlib.sha256(); size = 0
        for chunk in iter(lambda: previous.read(1024 * 1024), b''):
            value.update(chunk); size += len(chunk)
            if output is not None: output.write(chunk)
        previous.close()
        if output is not None: output.close()
        statuses = [child.wait() for child in children]
        if any(statuses): raise ValueError('Archive tool failed: ' + str(statuses))
        return {'sha256': value.hexdigest(), 'bytes': size}
    finally:
        for child in children:
            if child.poll() is None: child.kill()
        for child in children: child.wait()
        if previous is not None: previous.close()
        if output is not None: output.close()
def file_digest(path):
    value = hashlib.sha256(); size = 0
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(chunk); size += len(chunk)
    return {'sha256': value.hexdigest(), 'bytes': size}
if mode == 'external':
    tarballs = pathlib.Path(tree)
    original = json.loads((offer / 'notices/compiler-object-cleanup.json').read_text())['original_tarballs']
    def verify_external_inputs():
        rows = []
        for path in [tarballs, *sorted(tarballs.rglob('*'))]:
            info = path.lstat(); kind = 'directory' if stat.S_ISDIR(info.st_mode) else 'file'
            if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                raise ValueError('Original external source must remain a regular file/directory')
            row = {'path': path.relative_to(tarballs).as_posix(), 'mode': stat.S_IMODE(info.st_mode), 'type': kind}
            if kind == 'file': row.update(file_digest(path))
            rows.append(row)
        if sorted(rows, key=lambda r: r['path']) != sorted(original, key=lambda r: r['path']):
            raise ValueError('Original external source inventory changed')
    verify_external_inputs()
    command = ['tar', '-C', str(tarballs.parent), '-cf', '-', tarballs.name]
    destination = offer / 'engine-external-sources.tar.zst'
    expected = {'raw': measured([command])}
else:
    command = ['git', '-c', 'tar.umask=0022', 'archive', '--format=tar', '--mtime=@' + epoch, tree]
    checkpoint = offer / 'notices/preheavy-source-archive.json'
    destination = offer / 'online-source.tar.zst' if mode == 'final' else None
    if mode not in ('preflight', 'verify', 'final'): raise ValueError('Unknown source archive operation')
    raw = measured([command])
    if mode != 'preflight':
        expected = json.loads(checkpoint.read_text())
        if (expected.get('schema') != 'preheavy-source-archive/1' or expected.get('tree') != tree
                or expected.get('epoch') != epoch or expected.get('raw') != raw):
            raise ValueError('Preheavy source archive identity changed')
compressed = measured([command, ['zstd', '-q', '-T1']], destination)
if mode == 'preflight':
    if measured([command, ['zstd', '-q', '-T1'], ['zstd', '-q', '-d', '-c']]) != raw:
        raise ValueError('Preheavy complete archive roundtrip failed')
    with checkpoint.open('x') as stream:
        json.dump({'schema': 'preheavy-source-archive/1', 'tree': tree, 'epoch': epoch,
                   'raw': raw, 'compressed': compressed}, stream, sort_keys=True, indent=2)
        stream.write('\n')
elif mode in ('verify', 'final') and expected.get('compressed') != compressed:
    raise ValueError('Real compressed source archive differs from preheavy measurement')
if destination is not None:
    if file_digest(destination) != compressed: raise ValueError('Archive byte readback failed')
    if measured([['zstd', '-q', '-d', '-c', str(destination)]]) != expected['raw']:
        raise ValueError('Full decompressed archive differs from original source stream')
    if mode == 'external': verify_external_inputs()
    proof = {'schema': 'source-archive-readback/1', 'archive': destination.name,
             'compressed': compressed, 'raw': expected['raw'], 'full_readback': True}
    (offer / 'notices' / (destination.name + '.readback.json')).write_text(json.dumps(proof, sort_keys=True, indent=2) + '\n')
SOURCE_ARCHIVE
}

release_compiler_objects() {
    # No make follows this call. Keep all original and transformed sources.
    verify_source_inputs || return 1
    test "$(git write-tree)" = "$(cat "$1/notices/preheavy-source-tree.txt")" || return 1
    git diff --cached --binary HEAD | cmp "$1/preheavy-source-changes.patch" - || return 1
    archive_source_tree verify "$1" "$(git write-tree)" || return 1
    python3 - "$1" "$2" "$3" <<'OBJECT_CLEANUP'
import hashlib, json, os, pathlib, re, shutil, stat, subprocess, sys
if any(pathlib.Path(value).is_symlink() for value in sys.argv[1:]):
    raise ValueError('Redirected protected inventory root rejected')
offer, installed, tarballs = [pathlib.Path(value).resolve() for value in sys.argv[1:]]
root = pathlib.Path(subprocess.check_output(['git', 'rev-parse', '--show-toplevel'], text=True).strip()).resolve()
work = root / 'engine/workdir'
candidates = [work / name for name in ('CObject', 'CxxObject')]
def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''): value.update(chunk)
    return value.hexdigest()
def within(path, parent): return path == parent or parent in path.parents
def mounts():
    if sys.platform != 'linux': return []  # Portable fixture; production is Linux.
    lines = pathlib.Path('/proc/self/mountinfo').read_text().splitlines()
    if not lines: raise ValueError('Actual mount inventory required')
    return [pathlib.Path(re.sub(r'\\([0-7]{3})', lambda m: chr(int(m[1], 8)), line.split()[4])) for line in lines]
def inventory(base, runtime=False):
    if base.is_symlink() or not base.is_dir(): raise ValueError('Regular inventory root required')
    rows = []
    def visit(path):
        info = path.lstat(); row = {'path': path.relative_to(base).as_posix(), 'mode': stat.S_IMODE(info.st_mode)}
        if stat.S_ISDIR(info.st_mode):
            row['type'] = 'directory'; rows.append(row)
            for child in sorted(path.iterdir()): visit(child)
        elif stat.S_ISREG(info.st_mode):
            row.update(type='file', bytes=info.st_size, sha256=digest(path)); rows.append(row)
        elif stat.S_ISLNK(info.st_mode) and runtime:
            target = os.readlink(path); row.update(type='symlink', target=target); rows.append(row)
            if os.path.isabs(target):
                normalized = pathlib.Path(os.path.normpath(target))
                resolved = normalized.resolve()
                if any(within(value, parent) for value in (normalized, resolved)
                       for parent in (root, tarballs, pathlib.Path('/build'))):
                    raise ValueError('Installed symlink depends on build sources')
            else:
                normalized = pathlib.Path(os.path.normpath(str(path.parent / target)))
                if not within(normalized, base): raise ValueError('Installed symlink escapes staged runtime')
        else: raise ValueError('Unknown file type in protected inventory: ' + str(path))
    visit(base); return rows
if work.resolve() != work or not work.is_dir(): raise ValueError('Own regular workdir required')
layout = root / 'engine/solenv/gbuild/TargetLocations.mk'
if layout.is_symlink() or digest(layout) != '1d7aad63b908062d465da2832f586df2db018fe16c37ec5ef1a8e69c4aac5193':
    raise ValueError('Exact pinned gbuild object layout required')
mount_points = mounts(); objects = []; allocation = 0
for candidate in candidates:
    if candidate.is_symlink() or candidate.resolve() != candidate: raise ValueError('Object path redirection rejected')
    if not candidate.exists(): continue
    if not candidate.is_dir(): raise ValueError('Object directory required')
    if any(within(mount, candidate) for mount in mount_points): raise ValueError('Mounted object subtree rejected')
    tracked = subprocess.check_output(['git', 'ls-files', '-z', '--', candidate.relative_to(root).as_posix()])
    if tracked: raise ValueError('Tracked source in object subtree rejected')
    for path in [candidate, *candidate.rglob('*')]:
        info = path.lstat()
        if info.st_dev != work.stat().st_dev or os.path.ismount(path): raise ValueError('Foreign filesystem rejected')
        if stat.S_ISDIR(info.st_mode): continue
        if not stat.S_ISREG(info.st_mode) or path.suffix not in ('.o', '.dwo'):
            raise ValueError('Only pinned C/C++ object outputs may be removed: ' + str(path))
        objects.append(path.relative_to(root).as_posix()); allocation += info.st_blocks * 512
before = inventory(installed, runtime=True); sources = inventory(tarballs); notices = inventory(offer)
free_before = shutil.disk_usage(work).free
report = {'schema': 'compiler-object-cleanup/1', 'phase': 'validated-before-unlink',
          'candidates': [str(p.relative_to(root)) for p in candidates], 'objects': objects,
          'object_allocated_bytes_upper_bound': allocation, 'installed_before': before,
          'original_tarballs': sources, 'offer_before': notices, 'free_before_bytes': free_before,
          'source_trees_and_original_tarballs_preserved': True, 'capacity_pass': False}
proof = offer / 'notices/compiler-object-cleanup.json'
with proof.open('x') as stream: json.dump(report, stream, sort_keys=True, indent=2); stream.write('\n')
for candidate in candidates:
    if candidate.exists(): shutil.rmtree(candidate)
after = inventory(installed, runtime=True)
if before != after or sources != inventory(tarballs): raise ValueError('Protected installation or source bytes changed')
# The proof itself is the only newly written offer file.
actual_notices = [row for row in inventory(offer) if row['path'] != 'notices/compiler-object-cleanup.json']
if actual_notices != notices: raise ValueError('Protected source/notice offer changed')
free_after = shutil.disk_usage(work).free
report.update(phase='completed', installed_after=after, installed_unchanged=True,
              free_after_bytes=free_after, free_delta_bytes=free_after-free_before)
proof.write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
print('[source-build] compiler_objects_unlinked=' + str(len(objects)) + ' free_delta_bytes=' + str(free_after-free_before))
OBJECT_CLEANUP
}

record_source_preflight() {
    offer=$1
    verify_source_inputs || return 1
    for source_notice in COPYING engine/COPYING.MPL engine/COPYING.LGPL; do
        test -s "$source_notice" || return 1
    done
    test "$(sha256sum engine/solenv/gbuild/TargetLocations.mk | cut -d ' ' -f1)" = 1d7aad63b908062d465da2832f586df2db018fe16c37ec5ef1a8e69c4aac5193 || return 1
    archive_source_tree preflight "$offer" "$(git write-tree)" || return 1
    git write-tree > "$offer/notices/preheavy-source-tree.txt" || return 1
    git diff --cached --binary HEAD > "$offer/preheavy-source-changes.patch" || return 1
}

archive_source_inputs() {
    offer=$1
    tarballs=$2
    argon2_license=$3
    # Refuse any change outside both exact reviewed preheavy source fixes.
    verify_source_inputs || return 1
    test "$(git write-tree)" = "$(cat "$offer/notices/preheavy-source-tree.txt")" || return 1
    test "$(sha256sum "$tarballs/phc-winner-argon2-20190702.tar.gz" | cut -d ' ' -f1)" = daf972a89577f8772602bf2eb38b6a3dd3d922bf5724d45e7f9589b5e830442c
    test "$(sha256sum "$argon2_license" | cut -d ' ' -f1)" = 220f8736a89ff51c92ef3d497f413b48e6cf1df3d6278bc909c6308c78e1718e
    cp "$argon2_license" "$offer/notices/argon2-LICENSE"
    git diff --cached --binary HEAD > "$offer/upstream-changes.patch"
    cmp "$offer/preheavy-source-changes.patch" "$offer/upstream-changes.patch" || return 1
    source_tree=$(git write-tree)
    # HEAD would omit our fix. Archive the exact staged source tree instead.
    # The fixed mtime avoids the current-time default for a tree object.
    archive_source_tree final "$offer" "$source_tree" || return 1
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
        'modified_sha256': digest(pathlib.Path('engine/RepositoryExternal.mk'))},
        {'path': 'browser/css/qtapp-tabstrip.css',
         'original_sha256': '01dd2b158aa38c2165b003cab20f667f0b8bf02e68e26cfde1107c431d332694',
         'modified_sha256': digest(pathlib.Path('browser/css/qtapp-tabstrip.css'))}],
    'preheavy_source_tree': {'path': 'notices/preheavy-source-tree.txt',
        'sha256': digest(offer / 'notices/preheavy-source-tree.txt')},
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
# BEGIN FONT CONFIGURATION CHECK
verify_font_configuration() {
    font_config=${1:-config_host.mk}
    for font_key in BUILD_TYPE WITH_FONTS DO_FETCH_TARBALLS; do
        font_lines=$(grep -c "^export $font_key=" "$font_config") || return 1
        test "$font_lines" -eq 1 || return 1
    done
    grep -Fx 'export WITH_FONTS=TRUE' "$font_config" >/dev/null || return 1
    grep -Fx 'export DO_FETCH_TARBALLS=TRUE' "$font_config" >/dev/null || return 1
    font_types=$(sed -n 's/^export BUILD_TYPE=//p' "$font_config") || return 1
    printf '%s\n' "$font_types" | awk '
        {for(i=1;i<=NF;i++) {
            if($i !~ /^[A-Za-z0-9_]+$/ || $i=="NOTO_FONT") bad=1
            if($i=="MORE_FONTS") standard++
        }}
        END {exit (bad || standard!=1)}' || return 1
}
# END FONT CONFIGURATION CHECK
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
apply_browser_source_fix
export SOURCE_DATE_EPOCH="$(git show -s --format=%ct HEAD)"
export MAKEFLAGS=-j1
mkdir -p /build/tarballs /build/instdir /build/offer/notices
cd /build/online/engine
./autogen.sh --with-distro=CPLinux-LOKit --without-package-format \
    --disable-symbols --without-java --with-lang=en-US \
    --with-fonts --disable-noto-font \
    --without-system-argon2 --with-parallelism=1 --with-external-tar=/build/tarballs
# Keep the standard font collection. Only the optional large additional Noto
# collection is excluded; the runtime's packaged CJK/DejaVu fonts stay present.
# BUILD_TYPE is the actual module/download selector, not an unexported option.
verify_font_configuration config_host.mk
grep -E '^export (BUILD_TYPE|WITH_FONTS|DO_FETCH_TARBALLS)=' config_host.mk > /build/offer/notices/engine-font-policy.txt
# Release configure permits a not-yet-installed runtime; headers and engine
# configuration are present. Use the unchanged offline upstream npm target.
cd /build/online
./autogen.sh
./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var \
    --disable-tests --with-lokit-path=/build/online/engine/include \
    --with-lo-path=/opt/collaboraoffice
preflight_browser_sources
record_source_preflight /build/offer
printf '[source-build] source_preflight=passed source_tree=%s\n' "$(cat /build/offer/notices/preheavy-source-tree.txt)"
cd /build/online/engine
printf '[source-build] standard_fonts=true optional_extra_noto=false\n'
verify_source_inputs
make -j1
mkdir -p /build/instdir/opt
# One filesystem: retain the same installed files through hard links instead
# of allocating a second complete engine copy. No source/output file is edited
# through these links; upstream source trees are archived before cleanup.
cp -al instdir /build/instdir/opt/collaboraoffice
cd /build/online
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
# BEGIN FINAL SOURCE ARCHIVES
release_compiler_objects /build/offer /build/instdir /build/tarballs
archive_source_inputs /build/offer /build/tarballs /build/online/engine/workdir/UnpackedTarball/argon2/LICENSE
archive_source_tree external /build/offer /build/tarballs
# END FINAL SOURCE ARCHIVES
apk info -v > /build/offer/notices/build-apk-versions.txt
apk info -a > /build/offer/notices/build-apk-metadata.txt
printf '%s\n' '{"schema":"source-evidence-status/1","public_binary_distribution":"blocked","complete_corresponding_source_verified":false,"remaining":["exact runtime/base APK inventory and corresponding sources","complete component-license and source closure bound to the image digest"]}' > /build/offer/source-closure-status.json
printf '%s\n' "$UPSTREAM_COMMIT" > /build/offer/notices/upstream-commit.txt
cd /build/offer
find . -type f ! -name SHA256SUMS -exec sha256sum '{}' \; | sort > SHA256SUMS
