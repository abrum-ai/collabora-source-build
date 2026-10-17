#!/usr/bin/env python3
"""Collect existing OCI/source evidence; never build an engine or change visibility.

MPL-2.0. Mechanical coverage/hash checks do not replace an independent license
review. Unknown packages, missing sources and incomplete reviews fail closed.
"""
import argparse
import base64
import hashlib
import gzip
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile
import urllib.request
import urllib.error
import zipfile

DIGEST = re.compile(r'sha256:[0-9a-f]{64}\Z')
COMMIT = re.compile(r'[0-9a-f]{40}\Z')
NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.+-]*\Z')
MAX_FILE = 2 * 1024**3


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for part in iter(lambda: stream.read(1024**2), b''):
            h.update(part)
    return h.hexdigest()


def save(path, value):
    Path(path).write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')


def relative(name):
    while name.startswith('./'):
        name = name[2:]
    p = PurePosixPath(name)
    need(name and not p.is_absolute() and '..' not in p.parts and '\\' not in name
         and '\x00' not in name, 'Unsafe archive path')
    return p.as_posix()


def scoped(root, name):
    p = Path(root) / relative(name)
    need(p.is_file() and not p.is_symlink() and p.resolve().is_relative_to(Path(root).resolve()),
         'Missing or escaping evidence file: ' + name)
    return p


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def github(path):
    need(path.startswith(('repos/', 'orgs/', 'users/')) and '..' not in path,
         'Explicit GitHub API path required')
    token = os.environ.get('GH_TOKEN')
    need(bool(token), 'Scoped workflow credential required')
    req = urllib.request.Request('https://api.github.com/' + path, headers={
        'Authorization': 'Bearer ' + token, 'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2026-03-10'})
    with urllib.request.build_opener(NoRedirect()).open(req, timeout=30) as reply:
        return json.load(reply)


def package(repository, visibility, name=None, expected_id=None, allow_seed=False):
    parts = repository.split('/')
    need(len(parts) == 2 and all(NAME.fullmatch(p) for p in parts), 'Explicit repository required')
    owner, repo = parts
    name = name or repo
    need(NAME.fullmatch(name) and visibility in ['private', 'public'], 'Explicit package policy required')
    meta = github('repos/' + repository)
    need(meta['full_name'].lower() == repository.lower() and meta['private'] is False
         and meta.get('visibility') == 'public',
         'Public build repository required')
    collection = 'orgs' if meta['owner']['type'] == 'Organization' else 'users'
    try:
        p = github(collection + '/' + owner + '/packages/container/' + name)
    except urllib.error.HTTPError as error:
        # Only an actual package 404 after confirming the public repository
        # admits the new, narrowly named license-only seed. Never a binary.
        if allow_seed and error.code == 404 and name in [repo + '-runtime-public', repo + '-sources-public']:
            return None
        raise
    need(type(p.get('id')) is int and p['id'] > 0 and p.get('package_type') == 'container'
         and p.get('visibility') == visibility and p.get('name', '').lower() == name.lower()
         and p.get('owner', {}).get('login', '').lower() == owner.lower()
         and p.get('repository', {}).get('id') == meta['id']
         and p.get('repository', {}).get('full_name', '').lower() == repository.lower(),
         'Actual package identity/visibility/repository binding does not match')
    need(expected_id is None or p['id'] == expected_id, 'Package identity changed')
    return {'id': p['id'], 'name': name, 'visibility': visibility,
            'repository': repository, 'repository_id': meta['id'], 'collection': collection,
            'html_url': p.get('html_url')}


def bind(repository, run_id, commit, arch, runtime, sources):
    need(COMMIT.fullmatch(commit) and arch in ['arm64', 'amd64']
         and DIGEST.fullmatch(runtime) and DIGEST.fullmatch(sources), 'Exact build inputs required')
    p = package(repository, 'private')
    run = github(f'repos/{repository}/actions/runs/{run_id}')
    need(run.get('id') == run_id and run.get('repository', {}).get('id') == p['repository_id']
         and run.get('head_repository', {}).get('id') == p['repository_id']
         and run.get('head_sha') == commit and run.get('event') == 'workflow_dispatch'
         and run.get('path') == '.github/workflows/source-build.yml'
         and run.get('display_title') == f'Full Collabora source build ({arch})'
         and run.get('status') == 'completed' and run.get('conclusion') == 'success',
         'Original successful same-repository source build is required')
    tags = {f'private-runtime-{commit}-{run_id}-{arch}': runtime,
            f'private-source-evidence-{commit}-{run_id}-{arch}': sources}
    found = {}
    for page in range(1, 101):
        versions = github(f"{p['collection']}/{repository.split('/')[0]}/packages/container/{p['name']}/versions?per_page=100&page={page}")
        for version in versions:
            for tag in version.get('metadata', {}).get('container', {}).get('tags', []):
                if tag in tags:
                    need(version.get('name') == tags[tag], 'Staging tag no longer matches original digest')
                    need(tag not in found, 'Ambiguous registry tag')
                    found[tag] = version['name']
        if len(found) == len(tags) or len(versions) < 100:
            break
    need(found == tags, 'Both original private staging versions must be observed')
    recipe = {}
    for name in ['Dockerfile', 'build-source.sh', 'upstream.lock.json']:
        item = github(f'repos/{repository}/contents/docker/own-source-build/{name}?ref={commit}')
        need(item.get('encoding') == 'base64', 'Actual build recipe bytes required')
        recipe[name] = hashlib.sha256(base64.b64decode(item['content'])).hexdigest()
    return {'schema': 'source-build-binding/1', 'repository': repository,
            'build_run_id': run_id, 'build_commit': commit, 'architecture': arch,
            'runtime_digest': runtime, 'source_evidence_digest': sources, 'package': p,
            'build_url': run['html_url'], 'staging_tags': tags, 'recipe_files_sha256': recipe}


def tag_state(repository, name, visibility, expected_id, tag, digest):
    need(NAME.fullmatch(tag) and DIGEST.fullmatch(digest), 'Exact immutable publication tag/digest required')
    p = package(repository, visibility, name, expected_id)
    for page in range(1, 101):
        versions = github(f"{p['collection']}/{repository.split('/')[0]}/packages/container/{name}/versions?per_page=100&page={page}")
        matches = [v for v in versions if tag in v.get('metadata', {}).get('container', {}).get('tags', [])]
        need(len(matches) <= 1, 'Ambiguous publication tag')
        if matches:
            need(matches[0].get('name') == digest, 'Existing publication tag has another digest; never overwrite')
            return {'state': 'already-present', 'package': p, 'tag': tag, 'digest': digest}
        if len(versions) < 100:
            return {'state': 'absent', 'package': p, 'tag': tag, 'digest': digest}
    raise ValueError('Version listing is incomplete; no publication admission')


def blob(layout, descriptor):
    digest = descriptor.get('digest', '')
    need(DIGEST.fullmatch(digest), 'Only exact SHA256 OCI descriptors are supported')
    p = scoped(layout, 'blobs/sha256/' + digest[7:])
    need(sha(p) == digest[7:] and p.stat().st_size == descriptor.get('size'), 'OCI content mismatch')
    return p


def image(layout, digest, arch):
    need(DIGEST.fullmatch(digest), 'Exact OCI image digest required')
    p = scoped(layout, 'blobs/sha256/' + digest[7:])
    need(sha(p) == digest[7:] and p.stat().st_size < 8 * 1024**2, 'OCI root mismatch')
    root = json.loads(p.read_text())
    if 'manifests' in root:
        matches = [d for d in root['manifests'] if d.get('platform', {}).get('os') == 'linux'
                   and d.get('platform', {}).get('architecture') == arch]
        need(len(matches) == 1, 'Exactly one requested Linux platform is required')
        for descriptor in root['manifests']:
            if descriptor in matches:
                continue
            # --all must not ship another, uninventoried runtime platform.
            # BuildKit provenance descriptors may accompany the single image;
            # they contain in-toto JSON, never an additional filesystem layer.
            need(descriptor.get('platform') == {'architecture': 'unknown', 'os': 'unknown'}
                 and descriptor.get('annotations', {}).get('vnd.docker.reference.type') == 'attestation-manifest',
                 'Uninventoried runtime platform in OCI index')
            attestation = json.loads(blob(layout, descriptor).read_text())
            blob(layout, attestation['config'])
            for layer in attestation['layers']:
                need(layer.get('mediaType', '').startswith('application/vnd.in-toto+json'),
                     'Attestation descriptor contains a filesystem layer')
                p = blob(layout, layer)
                need(p.stat().st_size < 32 * 1024**2, 'Oversized provenance JSON')
                json.loads(p.read_text())
        descriptor = matches[0]
        root = json.loads(blob(layout, descriptor).read_text())
    need(root.get('schemaVersion') == 2 and isinstance(root.get('layers'), list), 'OCI image manifest required')
    config = json.loads(blob(layout, root['config']).read_text())
    need(config.get('os') == 'linux' and config.get('architecture') == arch, 'Image config platform mismatch')
    for layer in root['layers']:
        blob(layout, layer)
    return root, config


def members(path, media=''):
    process = None
    if media.endswith('+zstd') or str(path).endswith('.zst'):
        process = subprocess.Popen(['zstd', '-dc', '--', str(path)], stdout=subprocess.PIPE)
        stream = tarfile.open(fileobj=process.stdout, mode='r|')
    else:
        stream = tarfile.open(path, mode='r|*')
    try:
        with stream:
            for entry in stream:
                if entry.isdir() and not entry.name.strip('./'):
                    continue
                name = relative(entry.name)
                need(entry.size <= MAX_FILE, 'Oversized archive member')
                yield name, entry, stream
    finally:
        if process:
            process.stdout.close()
            need(process.wait() == 0, 'Zstd archive decoding failed')


def apk_database(raw):
    result = []
    for block in raw.decode('utf-8').strip().split('\n\n'):
        fields = {}
        for line in block.splitlines():
            if len(line) > 1 and line[1] == ':' and line[0] not in fields:
                fields[line[0]] = line[2:]
        if not fields:
            continue
        need(all(fields.get(k) for k in ['C', 'P', 'V', 'A', 'L', 'o', 'c']), 'APK source provenance missing')
        need(NAME.fullmatch(fields['P']) and NAME.fullmatch(fields['o']) and COMMIT.fullmatch(fields['c'])
             and re.fullmatch(r'[A-Za-z0-9_.+~:-]+', fields['V']),
             'Invalid APK origin/commit')
        result.append({'name': fields['P'], 'version': fields['V'], 'architecture': fields['A'],
                       'license': fields['L'], 'origin': fields['o'], 'aports_commit': fields['c'],
                       'apk_checksum': fields['C'], 'build_time': fields.get('t')})
    need(result, 'Nonempty APK inventory required')
    return result


def inventory(binding, runtime_layout, source_layout, dest):
    dest = Path(dest)
    need(not dest.exists(), 'Evidence directory must be new')
    runtime, config = image(runtime_layout, binding['runtime_digest'], binding['architecture'])
    source, _ = image(source_layout, binding['source_evidence_digest'], binding['architecture'])
    labels = config.get('config', {}).get('Labels', {})
    need(labels.get('org.opencontainers.image.source') == 'https://github.com/' + binding['repository']
         and labels.get('org.opencontainers.image.revision') == binding['build_commit'], 'Runtime build labels mismatch')
    dest.mkdir(parents=True)
    save(dest / 'build-binding.json', binding)
    offer = dest / 'source-evidence'
    offer.mkdir()
    # The source-evidence scratch target must contain regular files/directories
    # only. Never extract a symlink, device or arbitrary tar member on the host.
    for layer in source['layers']:
        for name, entry, archive in members(blob(source_layout, layer), layer['mediaType']):
            if entry.isdir():
                continue
            need(entry.isfile() and '.wh.' not in PurePosixPath(name).name, 'Unsafe source layer entry')
            target = offer / name
            need(not target.exists(), 'Duplicate source evidence path')
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open('xb') as out:
                data = archive.extractfile(entry)
                for part in iter(lambda: data.read(1024**2), b''):
                    out.write(part)
    sums = scoped(offer, 'SHA256SUMS').read_text().splitlines()
    expected = {}
    for line in sums:
        digest, name = line.split(maxsplit=1)
        name = relative(name.lstrip('*'))
        need(re.fullmatch(r'[0-9a-f]{64}', digest) and name not in expected, 'Invalid source checksum list')
        expected[name] = digest
        need(sha(scoped(offer, name)) == digest, 'Source archive checksum mismatch')
    actual = {p.relative_to(offer).as_posix() for p in offer.rglob('*') if p.is_file()}
    need(actual == set(expected) | {'SHA256SUMS'}, 'Unlisted or missing source evidence')
    for name, digest in binding['recipe_files_sha256'].items():
        need(sha(scoped(offer, name)) == digest, 'Source offer does not contain exact producing recipe')
    lock = json.loads(scoped(offer, 'upstream.lock.json').read_text())
    upstream = scoped(offer, 'notices/upstream-commit.txt').read_text().strip()
    need(COMMIT.fullmatch(upstream) and lock.get('commit') == upstream, 'Pinned upstream source mismatch')
    package_versions = {}
    layer_inventory = []
    extra_fonts = set()
    for layer in runtime['layers']:
        files, packages, fonts = [], [], []
        for name, entry, archive in members(blob(runtime_layout, layer), layer['mediaType']):
            record = {'path': name, 'type': entry.type.decode('ascii', errors='replace'), 'size': entry.size}
            if entry.isfile():
                data = archive.extractfile(entry)
                h = hashlib.sha256()
                database = io.BytesIO() if name == 'lib/apk/db/installed' else None
                for part in iter(lambda: data.read(1024**2), b''):
                    h.update(part)
                    if database is not None:
                        need(database.tell() + len(part) < 64 * 1024**2, 'APK database too large')
                        database.write(part)
                record['sha256'] = h.hexdigest()
                if database is not None:
                    packages = apk_database(database.getvalue())
                    for p in packages:
                        package_versions[(p['name'], p['version'], p['aports_commit'])] = p
            elif entry.issym() or entry.islnk():
                record['link'] = entry.linkname  # inventory only; never followed
            elif not entry.isdir():
                need(PurePosixPath(name).name.startswith('.wh.'), 'Unexpected runtime device/special file')
            if Path(name).suffix.lower() in ['.ttf', '.otf', '.ttc', '.woff', '.woff2']:
                fonts.append(record)
                extra_fonts.add(str(PurePosixPath(name).parent))
            files.append(record)
        layer_inventory.append({'digest': layer['digest'], 'files': files, 'apk_packages': packages, 'fonts': fonts})
    need(package_versions, 'No installed APK provenance observed in delivered layers')
    origins = {}
    for p in package_versions.values():
        ident = p['origin'] + '@' + p['aports_commit']
        origins.setdefault(ident, {'origin': p['origin'], 'commit': p['aports_commit'], 'packages': []})['packages'].append(p)
    save(dest / 'runtime-inventory.json', {'schema': 'runtime-layer-inventory/1', 'layers': layer_inventory})
    save(dest / 'apk-origins.json', list(origins.values()))
    sbom = json.loads(scoped(offer, 'notices/collabora-online-sbom.spdx.json').read_text())
    need(isinstance(sbom.get('packages'), list) and sbom['packages'], 'Actual SPDX package inventory required')
    components = {}
    for ident, origin in origins.items():
        components['apk:' + ident] = {'kind': 'apk', 'licenses': sorted({p['license'] for p in origin['packages']}),
                                      'source_archives_required': ['apk-sources/' + ident.replace('@', '-') + '.src.tar.gz']}
    for p in sbom['packages']:
        ident = p.get('SPDXID')
        need(isinstance(ident, str) and ident and 'engine:' + ident not in components, 'Unique SPDX package ID required')
        components['engine:' + ident] = {'kind': 'engine', 'name': p.get('name'), 'version': p.get('versionInfo'),
                                        'licenses': [p.get('licenseConcluded'), p.get('licenseDeclared')],
                                        'source_archives_required': ['source-evidence/online-source.tar.zst',
                                                                     'source-evidence/engine-external-sources.tar.zst']}
    for directory in sorted(extra_fonts):
        components['font-directory:' + directory] = {'kind': 'font', 'directory': directory}
    save(dest / 'components.json', components)
    save(dest / 'review-required.json', {'schema': 'source-closure-review/1',
        'runtime_digest': binding['runtime_digest'], 'source_evidence_digest': binding['source_evidence_digest'],
        'components_sha256': sha(dest / 'components.json'), 'inventory_sha256': sha(dest / 'runtime-inventory.json'),
        'independent_review': None, 'components': {k: {'license_decision': None, 'source_files': {}, 'notice_files': {}}
                                               for k in components}, 'public_distribution': 'blocked'})


def file_index(root):
    result = {}
    for p in Path(root).rglob('*'):
        need(not p.is_symlink(), 'Symlink is not source-closure evidence')
        if p.is_file():
            result[p.relative_to(root).as_posix()] = sha(p)
    return result


def seed_layout(repository, name, license_path, inputs_path, arch, dest):
    need(name in [repository.split('/')[-1] + '-runtime-public', repository.split('/')[-1] + '-sources-public'],
         'Only separate new public metadata targets may be seeded')
    need(arch in ['arm64', 'amd64'] and not Path(dest).exists(), 'New seed layout required')
    files = {'LICENSE': Path(license_path).read_bytes(), 'build-inputs.json': Path(inputs_path).read_bytes()}
    need(all(0 < len(raw) < 1024**2 for raw in files.values()), 'Only bounded license/input metadata is allowed')
    out = Path(dest)
    (out / 'blobs/sha256').mkdir(parents=True)
    def put(raw, media):
        digest = hashlib.sha256(raw).hexdigest()
        (out / 'blobs/sha256' / digest).write_bytes(raw)
        return {'mediaType': media, 'digest': 'sha256:' + digest, 'size': len(raw)}
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode='w') as tar:
        for path, raw in sorted(files.items()):
            entry = tarfile.TarInfo(path)
            entry.size, entry.mode, entry.mtime = len(raw), 0o444, 0
            tar.addfile(entry, io.BytesIO(raw))
    raw = archive.getvalue()
    layer = put(gzip.compress(raw, mtime=0), 'application/vnd.oci.image.layer.v1.tar+gzip')
    config = {'architecture': arch, 'os': 'linux', 'config': {'Labels': {
        'org.opencontainers.image.source': 'https://github.com/' + repository,
        'org.opencontainers.image.licenses': 'MPL-2.0',
        'org.opencontainers.image.description': 'License and build-input metadata only; no runtime or base layers'}},
        'rootfs': {'type': 'layers', 'diff_ids': ['sha256:' + hashlib.sha256(raw).hexdigest()]},
        'history': [{'created_by': 'COPY LICENSE build-inputs.json / (metadata only)'}]}
    descriptor = put(json.dumps(config, sort_keys=True).encode(), 'application/vnd.oci.image.config.v1+json')
    manifest = {'schemaVersion': 2, 'mediaType': 'application/vnd.oci.image.manifest.v1+json',
                'config': descriptor, 'layers': [layer]}
    image_descriptor = put(json.dumps(manifest, sort_keys=True).encode(), 'application/vnd.oci.image.manifest.v1+json')
    image_descriptor['annotations'] = {'org.opencontainers.image.ref.name': 'seed'}
    save(out / 'index.json', {'schemaVersion': 2, 'manifests': [image_descriptor]})
    save(out / 'oci-layout', {'imageLayoutVersion': '1.0.0'})
    return {'schema': 'license-only-seed/1', 'repository': repository, 'package_name': name,
            'digest': image_descriptor['digest'], 'layer_digest': layer['digest'], 'base_layers': 0,
            'files': {k: hashlib.sha256(v).hexdigest() for k, v in files.items()}, 'runtime_binaries': False}


def verify_seed(layout, digest, arch, license_path, inputs_path):
    manifest, config = image(layout, digest, arch)
    need(len(manifest['layers']) == 1 and len(config.get('history', [])) == 1, 'Unexpected seed ancestry')
    found = {}
    layer = manifest['layers'][0]
    for name, entry, archive in members(blob(layout, layer), layer['mediaType']):
        need(entry.isfile() and name in ['LICENSE', 'build-inputs.json'] and name not in found
             and entry.size < 1024**2, 'Seed contains more than license/input metadata')
        found[name] = hashlib.sha256(archive.extractfile(entry).read()).hexdigest()
    expected = {'LICENSE': sha(license_path), 'build-inputs.json': sha(inputs_path)}
    need(found == expected, 'Remote license-only seed mismatch')
    return {'digest': digest, 'files': found, 'base_layers': 0, 'runtime_binaries': False,
            'remote_content_verified': True}


def notice_bytes(root, reference):
    parts = reference.split('::')
    p = scoped(root, parts[0])
    if len(parts) == 1:
        need(p.stat().st_size <= 4 * 1024**2, 'Notice too large')
        return p.read_bytes()
    need(len(parts) <= 4, 'Too many nested source archives')
    raw = None
    for name in parts[1:]:
        name = relative(name)
        is_zip = str(p).endswith('.zip') if raw is None else zipfile.is_zipfile(io.BytesIO(raw))
        if is_zip:
            with zipfile.ZipFile(p if raw is None else io.BytesIO(raw)) as archive:
                entry = archive.getinfo(name)
                need(entry.file_size <= MAX_FILE, 'Oversized source member')
                raw = archive.read(entry)
        elif raw is None:
            result = None
            for member_name, entry, archive in members(p):
                if member_name == name:
                    need(entry.isfile(), 'Notice reference must be a regular file')
                    result = archive.extractfile(entry).read(MAX_FILE + 1)
                    # Consume zstd streams fully; an early close would mask
                    # archive errors or turn a valid notice into SIGPIPE.
            need(result is not None, 'Missing notice in source archive')
            raw = result
        else:
            with tarfile.open(fileobj=io.BytesIO(raw), mode='r:*') as archive:
                entry = archive.getmember(name)
                need(entry.isfile() and entry.size <= MAX_FILE, 'Invalid nested source member')
                raw = archive.extractfile(entry).read(MAX_FILE + 1)
        need(raw is not None and len(raw) <= MAX_FILE, 'Invalid source notice')
    need(len(raw) <= 4 * 1024**2, 'Final notice too large')
    return raw


def review(root, review_path, closure_digest):
    root = Path(root)
    r = json.loads(Path(review_path).read_text())
    b = json.loads(scoped(root, 'build-binding.json').read_text())
    components = json.loads(scoped(root, 'components.json').read_text())
    need(DIGEST.fullmatch(closure_digest) and r.get('closure_digest') == closure_digest
         and r.get('schema') == 'source-closure-review/1' and r.get('runtime_digest') == b['runtime_digest']
         and r.get('source_evidence_digest') == b['source_evidence_digest']
         and r.get('components_sha256') == sha(root / 'components.json')
         and r.get('inventory_sha256') == sha(root / 'runtime-inventory.json'), 'Review is not bound to these exact artifacts')
    independent = r.get('independent_review')
    need(isinstance(independent, dict) and all(isinstance(independent.get(k), str) and len(independent[k]) >= 8
         for k in ['reviewer', 'reference', 'scope']) and independent.get('scope') == 'all-delivered-components-and-source-obligations',
         'Recorded independent full-scope review is required; this validator does not perform it')
    need(isinstance(r.get('components'), dict) and set(r['components']) == set(components), 'Every delivered component must be reviewed')
    notices = root / 'verified-notices'
    notices.mkdir(exist_ok=True)
    for ident, component in components.items():
        decision = r['components'][ident]
        need(isinstance(decision, dict), 'Structured component review required')
        license_decision = decision.get('license_decision')
        need(isinstance(license_decision, str) and len(license_decision) > 2
             and license_decision.upper() not in ['UNKNOWN', 'NONE', 'NOASSERTION', 'TODO'], 'Unresolved component license: ' + ident)
        sources, texts = decision.get('source_files'), decision.get('notice_files')
        need(isinstance(sources, dict) and sources and isinstance(texts, dict) and texts, 'Actual source and notice evidence required: ' + ident)
        need(any(name.startswith(('source-evidence/', 'apk-sources/'))
                 and name.endswith(('.src.tar.gz', '.tar.zst')) for name in sources),
             'Component review must point to real source archives, not just metadata')
        for required in component.get('source_archives_required', []):
            need(required in sources, 'Exact APK source archive missing from review')
        for name, digest in sources.items():
            need(re.fullmatch(r'[0-9a-f]{64}', digest) and sha(scoped(root, name)) == digest, 'Reviewed source checksum mismatch')
        for reference, digest in texts.items():
            raw = notice_bytes(root, reference)
            need(raw and hashlib.sha256(raw).hexdigest() == digest, 'Reviewed license notice checksum mismatch')
            (notices / (digest + '.txt')).write_bytes(raw)
    # This is a mechanical evidence report, not a substitute for the named review.
    report = {'schema': 'source-closure-verification/1', 'build_binding': b, 'closure_digest': closure_digest,
              'review_sha256': sha(review_path), 'independent_review': independent,
              'component_count': len(components), 'mechanical_coverage_and_hash_checks': 'passed',
              'license_review_is_external': True, 'files': file_index(root)}
    return report


def extract_evidence(layout, digest, arch, destination):
    destination = Path(destination)
    need(not destination.exists(), 'Evidence destination must be new')
    manifest, _ = image(layout, digest, arch)
    destination.mkdir(parents=True)
    for layer in manifest['layers']:
        for name, entry, archive in members(blob(layout, layer), layer['mediaType']):
            if entry.isdir():
                continue
            need(entry.isfile() and '.wh.' not in PurePosixPath(name).name, 'Unexpected evidence layer entry')
            p = destination / name
            need(not p.exists(), 'Duplicate evidence path')
            p.parent.mkdir(parents=True, exist_ok=True)
            with p.open('xb') as out:
                stream = archive.extractfile(entry)
                for block in iter(lambda: stream.read(1024**2), b''):
                    out.write(block)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    p = commands.add_parser('bind')
    for name in ['repository', 'build-commit', 'runtime-digest', 'source-digest', 'output']:
        p.add_argument('--' + name, required=True)
    p.add_argument('--build-run', required=True, type=int)
    p.add_argument('--arch', required=True, choices=['arm64', 'amd64'])
    p = commands.add_parser('inventory')
    for name in ['binding', 'runtime-layout', 'source-layout', 'destination']:
        p.add_argument('--' + name, required=True)
    p = commands.add_parser('review')
    for name in ['evidence', 'review-file', 'output']:
        p.add_argument('--' + name, required=True)
    p.add_argument('--closure-digest', required=True)
    p = commands.add_parser('package')
    p.add_argument('--repository', required=True)
    p.add_argument('--name', required=True)
    p.add_argument('--visibility', required=True, choices=['public', 'private'])
    p.add_argument('--expected-id', type=int)
    p.add_argument('--allow-metadata-seed', action='store_true')
    p.add_argument('--output', required=True)
    p = commands.add_parser('seed-layout')
    for name in ['repository', 'name', 'license-file', 'inputs-file', 'destination', 'output']:
        p.add_argument('--' + name, required=True)
    p.add_argument('--arch', choices=['arm64', 'amd64'], default='arm64')
    p = commands.add_parser('extract-evidence')
    for name in ['layout', 'digest', 'destination']:
        p.add_argument('--' + name, required=True)
    p.add_argument('--arch', choices=['arm64', 'amd64'], required=True)
    p = commands.add_parser('tag-state')
    for name in ['repository', 'name', 'tag', 'digest', 'output']:
        p.add_argument('--' + name, required=True)
    p.add_argument('--visibility', required=True, choices=['private', 'public'])
    p.add_argument('--expected-id', required=True, type=int)
    p = commands.add_parser('verify-seed')
    for name in ['layout', 'digest', 'license-file', 'inputs-file', 'output']:
        p.add_argument('--' + name, required=True)
    p.add_argument('--arch', choices=['arm64', 'amd64'], default='arm64')
    args = parser.parse_args()
    if args.command == 'bind':
        save(args.output, bind(args.repository, args.build_run, args.build_commit, args.arch, args.runtime_digest, args.source_digest))
    elif args.command == 'inventory':
        inventory(json.loads(Path(args.binding).read_text()), args.runtime_layout, args.source_layout, args.destination)
    elif args.command == 'review':
        save(args.output, review(args.evidence, args.review_file, args.closure_digest))
    elif args.command == 'seed-layout':
        save(args.output, seed_layout(args.repository, args.name, args.license_file,
                                     args.inputs_file, args.arch, args.destination))
    elif args.command == 'verify-seed':
        save(args.output, verify_seed(args.layout, args.digest, args.arch, args.license_file, args.inputs_file))
    elif args.command == 'extract-evidence':
        extract_evidence(args.layout, args.digest, args.arch, args.destination)
    elif args.command == 'tag-state':
        save(args.output, tag_state(args.repository, args.name, args.visibility, args.expected_id, args.tag, args.digest))
    else:
        value = package(args.repository, args.visibility, args.name, args.expected_id, args.allow_metadata_seed)
        if value is None:
            raise SystemExit(3)
        save(args.output, value)


if __name__ == '__main__':
    try:
        main()
    except urllib.error.HTTPError as error:
        raise SystemExit('SOURCE_CLOSURE_UNVERIFIED: GitHub API HTTP ' + str(error.code) + '; no publication admission.')
    except ValueError as error:
        raise SystemExit('SOURCE_CLOSURE_UNVERIFIED: ' + str(error) + '. No public binary publication.')
    except (OSError, KeyError, tarfile.TarError, zipfile.BadZipFile):
        raise SystemExit('SOURCE_CLOSURE_UNVERIFIED: missing/invalid evidence. No public binary publication.')
