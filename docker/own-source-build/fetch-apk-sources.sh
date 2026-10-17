#!/bin/bash
# MPL-2.0. Fetch/check source only: never compile an engine or run APKBUILD on host.
set -euo pipefail
evidence=$(realpath "${1:?fresh evidence directory required}")
test "$RUNNER_ENVIRONMENT" = github-hosted
test "$RUNNER_OS" = Linux
test "$(id -u)" = 1001
test -f "$evidence/apk-origins.json"
mkdir "$evidence/apk-sources"
work=$(mktemp -d "$RUNNER_TEMP/apk-source-fetch.XXXXXX")
active=''
cleanup() {
  if test -n "$active"; then docker rm -f "$active" >/dev/null 2>&1 || true; fi
  # This script removes only its own fresh scratch checkout.
  rm -rf -- "$work"
}
trap cleanup EXIT
git init --bare "$work/aports.git"
git -C "$work/aports.git" remote add origin https://gitlab.alpinelinux.org/alpine/aports.git
docker build --pull=false --file Dockerfile.source-fetch --tag source-fetch-tool .
docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges:true \
  source-fetch-tool -c 'apk info -v abuild; abuild -h' > "$evidence/source-fetch-tool.txt"
python3 - "$evidence/apk-origins.json" > "$work/origins.tsv" <<'PY'
import json,re,sys
for row in json.load(open(sys.argv[1])):
    assert re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.+-]*',row['origin'])
    assert re.fullmatch(r'[0-9a-f]{40}',row['commit'])
    print(row['origin']+'\t'+row['commit'])
PY
count=0
while IFS=$'\t' read -r origin commit; do
  python3 -c 'import os; d=os.statvfs("."); assert d.f_bavail*d.f_frsize >= 8*1024**3'
  git -C "$work/aports.git" fetch --depth=1 --filter=blob:none origin "$commit"
  test "$(git -C "$work/aports.git" rev-parse FETCH_HEAD)" = "$commit"
  directory=''
  for repo in main community testing; do
    if git -C "$work/aports.git" cat-file -e "$commit:$repo/$origin/APKBUILD" 2>/dev/null; then
      test -z "$directory"  # no ambiguous origin
      directory="$repo/$origin"
    fi
  done
  test -n "$directory"
  git -C "$work/aports.git" archive --format=tar "$commit" "$directory" > "$work/recipe.tar"
  out="$work/output-$count"
  mkdir "$out"
  active="source-fetch-${GITHUB_RUN_ID:?}-$count"
  # Only the recipe and one fresh output directory are mounted. No Docker
  # socket, host HOME, registry configuration, GitHub token or SSH key enters.
  timeout --foreground 900 docker run --name "$active" --rm --read-only \
    --user 1001:1001 --cap-drop ALL --security-opt no-new-privileges:true \
    --memory 768m --memory-swap 768m --cpus 1 --pids-limit 128 \
    --tmpfs /tmp:rw,nosuid,size=64m --tmpfs /work:rw,nosuid,size=512m \
    --mount "type=bind,source=$work/recipe.tar,target=/recipe.tar,readonly" \
    --mount "type=bind,source=$out,target=/out" \
    source-fetch-tool -c '
      set -eu
      mkdir -p "$HOME"
      tar -xf /recipe.tar -C /work --no-same-owner
      cd "/work/$1"
      abuild -d -s /out/downloads listpkg > /out/packages.txt
      REPODEST=/out/package abuild -d -s /out/downloads validate fetch srcpkg
    ' sh "$directory"
  active=''
  python3 - "$evidence/apk-origins.json" "$origin" "$commit" "$out" <<'PY'
import json,pathlib,sys
rows=json.load(open(sys.argv[1]))
row=next(r for r in rows if r['origin']==sys.argv[2] and r['commit']==sys.argv[3])
paths={pathlib.PurePosixPath(v).name for v in (pathlib.Path(sys.argv[4])/'packages.txt').read_text().split()}
for pkg in row['packages']:
    assert pkg['name']+'-'+pkg['version']+'.apk' in paths, 'APKBUILD does not produce observed package/version'
PY
  mapfile -t archives < <(find "$out/package/src" -maxdepth 1 -type f -name '*.src.tar.gz')
  test "${#archives[@]}" = 1
  cp -- "${archives[0]}" "$evidence/apk-sources/$origin-$commit.src.tar.gz"
  cp -- "$work/recipe.tar" "$evidence/apk-sources/$origin-$commit.aports.tar"
  cp -- "$out/packages.txt" "$evidence/apk-sources/$origin-$commit.packages.txt"
  # The final source package includes the verified upstream archives, local
  # patches, APKBUILD, triggers and installation scripts. Preserve that exact
  # archive and recipe; discard only this source fetch's duplicate scratch data.
  rm -rf -- "$out"
  count=$((count + 1))
done < "$work/origins.tsv"
python3 - "$evidence" <<'PY'
import hashlib,json,pathlib,sys
root=pathlib.Path(sys.argv[1]); files={}
for p in sorted((root/'apk-sources').iterdir()):
    assert p.is_file() and not p.is_symlink()
    h=hashlib.sha256()
    with p.open('rb') as f:
        for block in iter(lambda:f.read(1024**2),b''):h.update(block)
    files[p.name]=h.hexdigest()
(root/'apk-source-checksums.json').write_text(json.dumps(files,sort_keys=True,indent=2)+'\n')
PY
