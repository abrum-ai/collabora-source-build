#!/usr/bin/env python3
"""Collect existing OCI/source evidence; never build an engine or change visibility.

MPL-2.0. Mechanical coverage/hash checks do not replace an independent license
review. Unknown packages, missing sources and incomplete reviews fail closed.
"""
import argparse
import base64
import bz2
import contextlib
import hashlib
import gzip
import io
import json
import lzma
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tempfile
import tarfile
import urllib.request
import urllib.error
import zipfile
import zlib

DIGEST = re.compile(r'sha256:[0-9a-f]{64}\Z')
COMMIT = re.compile(r'[0-9a-f]{40}\Z')
NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.+-]*\Z')
MAX_FILE = 2 * 1024**3
MAX_TAR_BYTES = 8 * 1024**3
MAX_TAR_PADDING = 1024**2
MAX_TAR_MEMBERS = 100000
INSPECTION_PREFIX = 'SOURCE_INSPECTION_V1 '
INSPECTION_TOTAL = 24 * 1024**2
INSPECTION_MEMBER = 4 * 1024**2
INSPECTION_CHUNK = 12 * 1024
INSPECTION_ARCHIVE_BUDGET = 8 * 1024**3
INSPECTION_INVENTORIES = ['build-binding.json', 'runtime-inventory.json', 'components.json', 'apk-origins.json',
                         'apk-source-checksums.json', 'review-required.json',
                         'source-evidence/notices/collabora-online-sbom.spdx.json']


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


def decoded_parts(source, codec):
    """Consume every compression frame/trailer; never ignore unused input."""
    factory = {'gzip': lambda: zlib.decompressobj(31), 'bzip2': bz2.BZ2Decompressor,
               'xz': lzma.LZMADecompressor}[codec]
    decoder, pending = factory(), source.read(64 * 1024)
    need(pending, 'Empty compressed TAR stream')
    try:
        while True:
            raw = decoder.decompress(pending, 64 * 1024)
            if raw:
                yield raw
            if decoder.eof:
                pending = decoder.unused_data or source.read(64 * 1024)
                if not pending:
                    return
                decoder = factory()
            elif codec == 'gzip':
                pending = decoder.unconsumed_tail or source.read(64 * 1024)
                need(pending, 'Truncated gzip TAR stream')
            elif decoder.needs_input:
                pending = source.read(64 * 1024)
                need(pending, 'Truncated compressed TAR stream')
            else:
                pending = b''
    except (zlib.error, OSError, EOFError, lzma.LZMAError):
        raise ValueError('Invalid or incomplete TAR compression stream') from None


class BoundedTarInfo(tarfile.TarInfo):
    """Bound extension metadata before the stdlib allocates or follows it."""
    @staticmethod
    def _check_header(info):
        need(0 <= info.size <= MAX_FILE and info.type != tarfile.GNUTYPE_SPARSE,
             'Oversized or unsupported sparse TAR header')
        if info.type in [tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.SOLARIS_XHDTYPE,
                         tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK]:
            need(info.size <= 4 * 1024**2, 'Oversized TAR extension metadata')
        return info

    @classmethod
    def frombuf(cls, buf, encoding, errors):
        if hasattr(tarfile.TarInfo, '_frombuf'):
            return cls._frombuf(buf, encoding, errors)
        return cls._check_header(super().frombuf(buf, encoding, errors))

    @classmethod
    def _frombuf(cls, buf, encoding, errors, *, dircheck=True):
        # Newer stdlibs use this directly for recursive PAX/GNU headers.
        return cls._check_header(super()._frombuf(buf, encoding, errors, dircheck=dircheck))

    @staticmethod
    @contextlib.contextmanager
    def _header_budget(archive):
        archive.strict_headers = getattr(archive, 'strict_headers', 0) + 1
        depth = getattr(archive, 'strict_depth', 0)
        need(archive.strict_headers <= MAX_TAR_MEMBERS and depth < 32, 'Excessive TAR extension headers')
        archive.strict_depth = depth + 1
        try:
            yield
        finally:
            archive.strict_depth = depth

    @classmethod
    def fromtarfile(cls, archive):
        # Select the actual stdlib dispatch without counting its public wrapper
        # and private implementation twice. Older stdlibs recurse via this hook.
        if hasattr(tarfile.TarInfo, '_fromtarfile'):
            return cls._fromtarfile(archive)
        with cls._header_budget(archive):
            return super().fromtarfile(archive)

    @classmethod
    def _fromtarfile(cls, archive, *, dircheck=True):
        with cls._header_budget(archive):
            return super()._fromtarfile(archive, dircheck=dircheck)

    def _proc_gnusparse_00(self, *args):
        raise ValueError('Sparse TAR metadata is unsupported')

    _proc_gnusparse_01 = _proc_gnusparse_00
    _proc_gnusparse_10 = _proc_gnusparse_00


def members(path, media='', limit=None):
    """One complete bounded TAR, validated before any consumer sees a member.

    A seekable decoded spool makes the logical first-end offset independent of
    parser/decompressor read-ahead. It is archive data, never an extracted tree.
    """
    limit = MAX_TAR_BYTES if limit is None else min(limit, MAX_TAR_BYTES)
    process = None
    try:
        with contextlib.ExitStack() as stack:
            if isinstance(path, bytes):
                source = stack.enter_context(tempfile.TemporaryFile(mode='w+b', buffering=0))
                source.write(path); source.seek(0)
            else:
                source = stack.enter_context(Path(path).open('rb', buffering=0))
            magic = source.read(6); source.seek(0)
            if media.endswith('+zstd') or magic.startswith(b'\x28\xb5\x2f\xfd'):
                process = subprocess.Popen(['zstd', '-dc'], stdin=source, stdout=subprocess.PIPE,
                                           stderr=subprocess.DEVNULL,
                                           env={'PATH': os.environ.get('PATH', os.defpath), 'LANG': 'C'})
                decoded = stack.enter_context(process.stdout)
                parts = iter(lambda: decoded.read(64 * 1024), b'')
            elif media.endswith('+gzip') or magic.startswith(b'\x1f\x8b'):
                parts = decoded_parts(source, 'gzip')
            elif magic.startswith(b'BZh'):
                parts = decoded_parts(source, 'bzip2')
            elif magic.startswith(b'\xfd7zXZ\x00'):
                parts = decoded_parts(source, 'xz')
            else:
                parts = iter(lambda: source.read(64 * 1024), b'')
            spool = stack.enter_context(tempfile.TemporaryFile(mode='w+b'))
            size = 0
            for part in parts:
                size += len(part)
                need(size <= limit, 'Decoded TAR budget exceeded')
                spool.write(part)
            if process:
                need(process.wait() == 0, 'Zstd archive decoding failed')
            need(size % tarfile.BLOCKSIZE == 0, 'Truncated or unaligned decoded TAR')
            spool.seek(0)
            archive = stack.enter_context(tarfile.open(fileobj=spool, mode='r:', ignore_zeros=False,
                                                      tarinfo=BoundedTarInfo))
            entries = []
            for entry in archive:
                need(len(entries) < MAX_TAR_MEMBERS and 0 <= entry.size <= MAX_FILE
                     and entry.sparse is None, 'Oversized or unsupported sparse TAR member')
                # Validate stored member padding as well as the final padding.
                end = entry.offset_data + entry.size
                following = archive.offset
                need(end <= following <= size and following - end < tarfile.BLOCKSIZE,
                     'Invalid TAR member extent')
                spool.seek(end)
                need(not any(spool.read(following - end)), 'Nonzero TAR member padding')
                name = None if entry.isdir() and not entry.name.strip('./') else relative(entry.name)
                entries.append((name, entry))
            end = archive.offset
            need(end % tarfile.BLOCKSIZE == 0 and 2 * tarfile.BLOCKSIZE <= size - end <= MAX_TAR_PADDING,
                 'Missing or excessive TAR end padding')
            spool.seek(end)
            for part in iter(lambda: spool.read(64 * 1024), b''):
                need(not any(part), 'Nonzero data or another archive after TAR end')
            for name, entry in entries:
                if name is not None:
                    yield name, entry, archive
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


def tar_member_bytes(path, name, limit=4 * 1024**2):
    """Read one unambiguous regular member without extracting an archive."""
    result = None
    for actual, entry, archive in members(path):
        if actual == name:
            need(result is None and entry.isfile() and 0 <= entry.size <= limit,
                 'Missing, duplicate or unsafe source member: ' + name)
            result = archive.extractfile(entry).read(limit + 1)
            need(len(result) == entry.size, 'Truncated source member: ' + name)
    need(result is not None, 'Missing source member: ' + name)
    return result


def collect_apk_source(origins_path, origin, commit, output, recipe, destination):
    """Admit container outputs as untrusted data before any host read/copy."""
    need(NAME.fullmatch(origin) and COMMIT.fullmatch(commit), 'Exact APK source identity required')
    output, destination, recipe = Path(output), Path(destination), Path(recipe)
    need(output.is_dir() and not output.is_symlink() and destination.is_dir()
         and not destination.is_symlink(), 'Regular source output directories required')
    rows = json.loads(Path(origins_path).read_text())
    rows = [r for r in rows if r.get('origin') == origin and r.get('commit') == commit]
    need(len(rows) == 1 and rows[0].get('packages'), 'Unique observed APK origin required')
    listing = scoped(output, 'packages.txt')
    need(listing.stat().st_size <= 4 * 1024**2, 'Oversized APK package list')
    packages = {PurePosixPath(v).name for v in listing.read_text().split()}
    need(all(p['name'] + '-' + p['version'] + '.apk' in packages for p in rows[0]['packages']),
         'APKBUILD does not produce observed package/version')
    directory = output / 'package/src'
    need(directory.is_dir() and not directory.is_symlink()
         and directory.resolve().is_relative_to(output.resolve()), 'Escaping APK source output directory')
    archives = list(directory.glob('*.src.tar.gz'))
    need(len(archives) == 1, 'Exactly one APK source archive required')
    archive = scoped(output, archives[0].relative_to(output).as_posix())
    need(0 < archive.stat().st_size <= MAX_FILE and recipe.is_file() and not recipe.is_symlink(),
         'Regular bounded APK source archive and recipe required')
    # srcpkg must retain the actual pinned APKBUILD, not a recipe rewritten by
    # an executed fetch hook. No archive tree is unpacked on the host.
    recipe_names = [name for name, entry, _ in members(recipe)
                    if name in [repo + '/' + origin + '/APKBUILD' for repo in ['main', 'community', 'testing']]]
    need(len(recipe_names) == 1, 'Unique pinned APKBUILD required')
    need(tar_member_bytes(recipe, recipe_names[0]) == tar_member_bytes(archive, origin + '/APKBUILD'),
         'Fetched source archive changed the pinned APKBUILD')
    sources = {origin + '-' + commit + '.src.tar.gz': archive,
               origin + '-' + commit + '.aports.tar': recipe,
               origin + '-' + commit + '.packages.txt': listing}
    need(all(not (destination / name).exists() and not (destination / name).is_symlink() for name in sources),
         'APK source evidence must not be replaced')
    result = {}
    for name, source in sources.items():
        with source.open('rb') as src, (destination / name).open('xb') as dest:
            for part in iter(lambda: src.read(1024**2), b''):
                dest.write(part)
        result[name] = sha(destination / name)
    return {'schema': 'apk-source-output/1', 'origin': origin, 'commit': commit, 'files': result}


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


def archive_is_zip(source):
    # is_zipfile() also accepts a ZIP appended to an unrelated TAR/executable.
    # Require an actual ZIP header so TAR tails cannot bypass the shared gate.
    if isinstance(source, bytes):
        magic = source[:4]
    elif isinstance(source, io.BytesIO):
        magic = source.getvalue()[:4]
    else:
        with Path(source).open('rb') as stream:
            magic = stream.read(4)
    return magic in [b'PK\x03\x04', b'PK\x05\x06']


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
        is_zip = archive_is_zip(p if raw is None else raw)
        if is_zip:
            with zipfile.ZipFile(p if raw is None else io.BytesIO(raw)) as archive:
                entry = archive.getinfo(name)
                need(entry.file_size <= MAX_FILE, 'Oversized source member')
                raw = archive.read(entry)
        else:
            raw = tar_member_bytes(p if raw is None else raw, name, MAX_FILE)
        need(raw is not None and len(raw) <= MAX_FILE, 'Invalid source notice')
    need(len(raw) <= 4 * 1024**2, 'Final notice too large')
    return raw


def review(root, review_path, closure_digest):
    root = Path(root)
    r = json.loads(Path(review_path).read_text())
    b = json.loads(scoped(root, 'build-binding.json').read_text())
    components = json.loads(scoped(root, 'components.json').read_text())
    need(isinstance(components, dict) and components, 'Nonempty delivered component inventory required')
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
        need(isinstance(component, dict), 'Structured component inventory required')
        kind = component.get('kind')
        if kind == 'apk':
            match = re.fullmatch(r'apk:([A-Za-z0-9][A-Za-z0-9_.+-]*)@([0-9a-f]{40})', ident)
            need(match is not None, 'Exact APK origin/commit component required')
            required_sources = ['apk-sources/' + match[1] + '-' + match[2] + '.src.tar.gz']
        elif kind == 'engine':
            need(ident.startswith('engine:') and len(ident) > len('engine:'), 'Engine component identity required')
            required_sources = ['source-evidence/online-source.tar.zst',
                                'source-evidence/engine-external-sources.tar.zst']
        elif kind == 'font':
            directory = component.get('directory')
            need(isinstance(directory, str) and relative(directory) == directory
                 and ident == 'font-directory:' + directory, 'Font source identity required')
            required_sources = []
        else:
            raise ValueError('Unsupported delivered component kind')
        # A missing/edited requirements list cannot silently lower coverage.
        need(component.get('source_archives_required', []) == required_sources,
             'Component source requirements changed')
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
        for required in required_sources:
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


def inspection_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            need(key not in result, 'Duplicate inspection JSON key')
            result[key] = value
        return result
    def constant(value):
        raise ValueError('Nonfinite inspection JSON value')
    try:
        return json.loads(raw, object_pairs_hook=unique, parse_constant=constant)
    except RecursionError:
        raise ValueError('Excessive inspection JSON nesting') from None


def inspection_path(name):
    need(isinstance(name, str) and 0 < len(name) <= 1024
         and not any(ord(c) < 32 or ord(c) == 127 for c in name)
         and relative(name) == name, 'Canonical bounded inspection path required')
    return name


def inspection_file(root, name):
    inspection_path(name)
    root = Path(root)
    need(root.is_dir() and not root.is_symlink(), 'Regular inspection root required')
    current = root
    for part in PurePosixPath(name).parts:
        current /= part
        need(not current.is_symlink(), 'Symlink in inspection path')
    return scoped(root, name)


def inspection_read(path, limit):
    need(Path(path).stat().st_size <= limit, 'Oversized inspection input')
    with Path(path).open('rb') as stream:
        raw = stream.read(limit + 1)
    need(len(raw) <= limit, 'Oversized inspection input')
    return raw


def inspection_member(source, name, limit):
    """Read an unambiguous regular member, without host extraction or execution."""
    if name is not None:
        inspection_path(name)
    if isinstance(source, bytes):
        source = io.BytesIO(source)
    result, listing, seen = None, [], set()
    listing_bytes, listed_data = 0, 0
    def collect(actual, size, kind, opener):
        nonlocal result, listing_bytes, listed_data
        if name is not None:
            if actual != name:
                return
            need(result is None and kind == 'file' and 0 <= size <= limit,
                 'Duplicate, linked, encrypted or oversized inspection member')
            with opener() as stream:
                result = stream.read(limit + 1)
            need(len(result) == size, 'Truncated inspection member')
            return
        need(actual not in seen and len(seen) < 100000 and 0 <= size <= MAX_FILE,
             'Ambiguous or oversized inspection archive index')
        seen.add(actual)
        record = {'path': actual, 'kind': kind, 'size': size}
        if kind == 'file':
            h, count = hashlib.sha256(), 0
            with opener() as stream:
                for part in iter(lambda: stream.read(64 * 1024), b''):
                    count += len(part); listed_data += len(part)
                    need(count <= size and listed_data <= INSPECTION_ARCHIVE_BUDGET,
                         'Inspection archive index decompression budget exceeded')
                    h.update(part)
            need(count == size, 'Truncated inspection archive index member')
            record['sha256'] = h.hexdigest()
        listing_bytes += len(json.dumps(record, sort_keys=True, ensure_ascii=True)) + 2
        need(listing_bytes <= limit - 256, 'Complete archive index exceeds the selected output budget')
        listing.append(record)
    if archive_is_zip(source):
        with zipfile.ZipFile(source) as archive:
            for entry in archive.infolist():
                actual = relative(entry.filename.rstrip('/'))
                kind = stat.S_IFMT(entry.external_attr >> 16)
                kind = 'directory' if entry.is_dir() else 'file' if kind in [0, stat.S_IFREG] else 'link-or-special'
                if entry.flag_bits & 1:
                    need(name is not None, 'Encrypted member cannot enter a complete archive index')
                    kind = 'encrypted'
                collect(actual, entry.file_size, kind, lambda: archive.open(entry))
    else:
        if isinstance(source, io.BytesIO):
            source = source.getvalue()
        for actual, entry, archive in members(source, limit=INSPECTION_ARCHIVE_BUDGET):
            kind = 'file' if entry.isfile() else 'directory' if entry.isdir() else 'link-or-special'
            collect(actual, entry.size, kind, lambda: archive.extractfile(entry))
    if name is None:
        return json.dumps({'schema': 'archive-member-index/1', 'complete': True, 'members': listing},
                          sort_keys=True, ensure_ascii=True).encode()
    need(result is not None, 'Missing inspection archive member')
    return result


def inspection_reference(root, reference):
    need(isinstance(reference, str) and len(reference) <= 4096, 'Bounded inspection reference required')
    parts = reference.split('::')
    need(1 <= len(parts) <= 4 and parts[0].startswith(('source-evidence/', 'apk-sources/')),
         'Inspection selects only candidate source evidence, not host files')
    for part in parts:
        inspection_path(part)
    source = inspection_file(root, parts[0])
    if len(parts) == 1:
        return inspection_read(source, INSPECTION_MEMBER)
    for index, member in enumerate(parts[1:]):
        limit = INSPECTION_MEMBER if index == len(parts) - 2 else 16 * 1024**2
        need(member != '@members' or index == len(parts) - 2, 'Archive index must end the inspection reference')
        source = inspection_member(source, None if member == '@members' else member, limit)
    return source


def inspection_context(binding, env=None):
    env = os.environ if env is None else env
    repository = binding['repository']
    need(env.get('GITHUB_REPOSITORY') == repository and env.get('GITHUB_EVENT_NAME') == 'workflow_dispatch'
         and env.get('RUNNER_ENVIRONMENT') == 'github-hosted' and env.get('RUNNER_OS') == 'Linux'
         and env.get('GITHUB_JOB') == 'inspect', 'Actual read-only inspection job required')
    commit = env.get('GITHUB_SHA', '')
    need(COMMIT.fullmatch(commit) and env.get('GITHUB_WORKFLOW_SHA') == commit,
         'Exact inspection workflow commit required')
    run_id, attempt = env.get('GITHUB_RUN_ID', ''), env.get('GITHUB_RUN_ATTEMPT', '')
    need(re.fullmatch(r'[1-9][0-9]*', run_id) and re.fullmatch(r'[1-9][0-9]*', attempt),
         'Actual inspection Run and Attempt required')
    meta = github('repos/' + repository)
    need(meta['id'] == binding['package']['repository_id'] and meta.get('private') is False
         and env.get('GITHUB_REF') == 'refs/heads/' + meta['default_branch'], 'Inspection default branch mismatch')
    run = github(f'repos/{repository}/actions/runs/{run_id}/attempts/{attempt}')
    workflow = '.github/workflows/source-qualification.yml'
    need(run.get('id') == int(run_id) and run.get('run_attempt') == int(attempt)
         and run.get('repository', {}).get('id') == meta['id']
         and run.get('head_repository', {}).get('id') == meta['id']
         and run.get('event') == 'workflow_dispatch' and run.get('head_sha') == commit
         and run.get('head_branch') == meta['default_branch'] and run.get('path') == workflow,
         'Inspection CI provenance mismatch')
    jobs = []
    for page in range(1, 11):
        batch = github(f'repos/{repository}/actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100&page={page}')['jobs']
        jobs.extend(j for j in batch if j.get('name') == 'inspect')
        if len(batch) < 100:
            break
    else:
        raise ValueError('Incomplete inspection job listing')
    need(len(jobs) == 1 and type(jobs[0].get('id')) is int and jobs[0]['id'] > 0
         and jobs[0].get('run_id') == int(run_id) and jobs[0].get('head_sha') == commit,
         'Unique actual inspection job required')
    return {'repository': repository, 'run_id': int(run_id), 'run_attempt': int(attempt),
            'job_id': jobs[0]['id'], 'job_key': 'inspect', 'workflow_commit': commit, 'workflow_path': workflow,
            'run_url': f'https://github.com/{repository}/actions/runs/{run_id}/attempts/{attempt}',
            'job_logs_api': f'https://api.github.com/repos/{repository}/actions/jobs/{jobs[0]["id"]}/logs',
            'helper_sha256': sha(__file__)}


def inspection_documents(root, binding, closure_digest, context, request=None):
    """Validate the complete snapshot before emitting even one untrusted byte."""
    root = Path(root)
    need(DIGEST.fullmatch(closure_digest), 'Exact closure digest required')
    embedded = inspection_json(inspection_read(inspection_file(root, 'build-binding.json'), INSPECTION_MEMBER))
    need(embedded == binding, 'Closure belongs to another freshly measured producer binding')
    request = request if request is not None else {'schema': 'source-inspection-request/1',
                                                  'closure_digest': closure_digest, 'references': []}
    need(isinstance(request, dict) and set(request) == {'schema', 'closure_digest', 'references'}
         and request['schema'] == 'source-inspection-request/1' and request['closure_digest'] == closure_digest,
         'Inspection request is not bound to this exact candidate')
    refs = request['references']
    need(isinstance(refs, list) and len(refs) <= 32 and all(isinstance(r, str) for r in refs)
         and len(set(refs)) == len(refs), 'Unique bounded inspection references required')
    documents = []
    total = 0
    def add(reference, raw):
        nonlocal total
        total += len(raw)
        need(total <= INSPECTION_TOTAL, 'Complete inspection exceeds the log budget; split explicit selections')
        documents.append((reference, raw))
    for name in INSPECTION_INVENTORIES:
        path = inspection_file(root, name)
        raw = inspection_read(path, 16 * 1024**2)
        need(isinstance(inspection_json(raw), (dict, list)), 'Structured inventory required')
        add(name, raw)
    index = {}
    for path in sorted(root.rglob('*')):
        need(not path.is_symlink() and (path.is_file() or path.is_dir()), 'Nonregular inspection evidence')
        if path.is_file():
            name = path.relative_to(root).as_posix()
            path = inspection_file(root, name)
            need(len(index) < 100000, 'Oversized inspection file index')
            index[name] = {'size': path.stat().st_size, 'sha256': sha(path)}
    add('@complete-file-index', json.dumps(index, sort_keys=True, ensure_ascii=True).encode())
    for reference in refs:
        need(reference not in [name for name, _ in documents], 'Duplicate inspection document')
        add(reference, inspection_reference(root, reference))
    manifest = {'schema': 'source-inspection/1', 'closure_digest': closure_digest, 'build_binding': binding,
                'ci': context, 'request_sha256': hashlib.sha256(json.dumps(request, sort_keys=True).encode()).hexdigest(),
                'legal_review_performed': False, 'complete_inventory': True,
                'documents': [{'reference': name, 'size': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
                               'chunks': (len(raw) + INSPECTION_CHUNK - 1) // INSPECTION_CHUNK}
                              for name, raw in documents]}
    return manifest, documents


def emit_inspection(manifest, documents, stream):
    encoded = json.dumps(manifest, sort_keys=True, ensure_ascii=True).encode()
    need(len(encoded) <= 32 * 1024, 'Inspection header exceeds the log record budget')
    digest = hashlib.sha256(encoded).hexdigest()
    def emit(record):
        stream.write(INSPECTION_PREFIX + json.dumps(record, sort_keys=True, ensure_ascii=True) + '\n')
    emit({'event': 'begin', 'manifest': manifest, 'manifest_sha256': digest})
    for number, (_, raw) in enumerate(documents):
        for chunk, start in enumerate(range(0, len(raw), INSPECTION_CHUNK)):
            emit({'event': 'chunk', 'manifest_sha256': digest, 'document': number, 'chunk': chunk,
                  'base64': base64.b64encode(raw[start:start + INSPECTION_CHUNK]).decode('ascii')})
    emit({'event': 'complete', 'manifest_sha256': digest, 'documents': len(documents)})


def decode_inspection(log, expected):
    """Verify saved raw CI logs; reject incomplete/duplicate/reordered frames."""
    need(len(log) <= 40 * 1024**2, 'Oversized raw inspection log')
    records = []
    for line in log.splitlines():
        line = re.sub(r'^\d{4}-\d\d-\d\dT[0-9:.]+Z ', '', line)
        if line.startswith(INSPECTION_PREFIX):
            need(len(line) <= 40 * 1024 and len(records) < 2200, 'Oversized inspection framing')
            record = inspection_json(line[len(INSPECTION_PREFIX):])
            need(isinstance(record, dict), 'Structured inspection frame required')
            records.append(record)
    need(len(records) >= 2 and records[0].get('event') == 'begin'
         and records[-1].get('event') == 'complete', 'Missing inspection completeness frames')
    manifest, digest = records[0]['manifest'], records[0]['manifest_sha256']
    need(isinstance(manifest, dict) and isinstance(manifest.get('ci'), dict)
         and isinstance(manifest.get('documents'), list) and 8 <= len(manifest['documents']) <= 40,
         'Structured complete inspection manifest required')
    need(hashlib.sha256(json.dumps(manifest, sort_keys=True, ensure_ascii=True).encode()).hexdigest() == digest,
         'Inspection manifest hash mismatch')
    need(manifest.get('schema') == 'source-inspection/1' and manifest.get('legal_review_performed') is False
         and manifest.get('complete_inventory') is True and manifest.get('closure_digest') == expected['closure_digest']
         and all(manifest['ci'].get(k) == expected[k] for k in ['run_id', 'run_attempt', 'job_id', 'workflow_commit']),
         'Inspection log does not match independently observed CI/candidate identity')
    need(records[-1] == {'event': 'complete', 'manifest_sha256': digest, 'documents': len(manifest['documents'])},
         'Inspection completion mismatch')
    documents, cursor, total = [], 1, 0
    for number, document in enumerate(manifest['documents']):
        need(isinstance(document, dict) and isinstance(document.get('reference'), str), 'Structured document metadata required')
        size = document['size']
        need(type(size) is int and 0 <= size <= INSPECTION_TOTAL
             and document['chunks'] == (size + INSPECTION_CHUNK - 1) // INSPECTION_CHUNK,
             'Invalid inspection document bounds')
        parts = []
        for chunk in range(document['chunks']):
            need(cursor < len(records) - 1, 'Truncated inspection chunks')
            record = records[cursor]; cursor += 1
            need(set(record) == {'event', 'manifest_sha256', 'document', 'chunk', 'base64'}
                 and record['event'] == 'chunk' and record['manifest_sha256'] == digest
                 and record['document'] == number and record['chunk'] == chunk, 'Duplicate or reordered inspection chunks')
            part = base64.b64decode(record['base64'], validate=True)
            need(len(part) == min(INSPECTION_CHUNK, size - chunk * INSPECTION_CHUNK), 'Truncated inspection chunk')
            parts.append(part)
        raw = b''.join(parts); total += len(raw)
        need(total <= INSPECTION_TOTAL and len(raw) == size
             and hashlib.sha256(raw).hexdigest() == document['sha256'], 'Inspection document content mismatch')
        documents.append((document['reference'], raw))
    need(cursor == len(records) - 1, 'Unexpected inspection frames')
    need([name for name, _ in documents[:8]] == INSPECTION_INVENTORIES + ['@complete-file-index']
         and len({name for name, _ in documents}) == len(documents), 'Incomplete or duplicate inspection inventories')
    return manifest, documents


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
    p = commands.add_parser('inspect')
    for name in ['repository', 'build-commit', 'runtime-digest', 'source-digest', 'closure-digest', 'layout', 'destination']:
        p.add_argument('--' + name, required=True)
    p.add_argument('--build-run', required=True, type=int)
    p.add_argument('--arch', required=True, choices=['arm64', 'amd64'])
    p.add_argument('--selection-file')
    p = commands.add_parser('decode-inspection')
    for name in ['log-file', 'closure-digest', 'workflow-commit', 'destination']:
        p.add_argument('--' + name, required=True)
    for name in ['run-id', 'run-attempt', 'job-id']:
        p.add_argument('--' + name, required=True, type=int)
    p = commands.add_parser('review')
    for name in ['evidence', 'review-file', 'output']:
        p.add_argument('--' + name, required=True)
    p.add_argument('--closure-digest', required=True)
    p = commands.add_parser('collect-apk-source')
    for name in ['origins', 'origin', 'commit', 'directory', 'recipe', 'destination', 'output']:
        p.add_argument('--' + name, required=True)
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
    elif args.command == 'inspect':
        need(DIGEST.fullmatch(args.closure_digest), 'Exact closure digest required')
        binding = bind(args.repository, args.build_run, args.build_commit, args.arch, args.runtime_digest, args.source_digest)
        context = inspection_context(binding)
        request = None
        if args.selection_file:
            request = inspection_json(inspection_read(args.selection_file, 64 * 1024))
        extract_evidence(args.layout, args.closure_digest, args.arch, args.destination)
        manifest, documents = inspection_documents(args.destination, binding, args.closure_digest, context, request)
        emit_inspection(manifest, documents, sys.stdout)
    elif args.command == 'decode-inspection':
        expected = {'closure_digest': args.closure_digest, 'workflow_commit': args.workflow_commit,
                    'run_id': args.run_id, 'run_attempt': args.run_attempt, 'job_id': args.job_id}
        raw = inspection_read(args.log_file, 40 * 1024**2).decode('utf-8')
        manifest, documents = decode_inspection(raw, expected)
        destination = Path(args.destination)
        need(not destination.exists() and not destination.is_symlink(), 'New inspection decode directory required')
        destination.mkdir(mode=0o700)
        save(destination / 'manifest.json', manifest)
        # Never turn untrusted member references into host paths.
        for index, (_, data) in enumerate(documents):
            (destination / (str(index).zfill(4) + '.bin')).write_bytes(data)
    elif args.command == 'review':
        save(args.output, review(args.evidence, args.review_file, args.closure_digest))
    elif args.command == 'collect-apk-source':
        save(args.output, collect_apk_source(args.origins, args.origin, args.commit,
                                           args.directory, args.recipe, args.destination))
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
    except (OSError, EOFError, KeyError, tarfile.TarError, zipfile.BadZipFile):
        raise SystemExit('SOURCE_CLOSURE_UNVERIFIED: missing/invalid evidence. No public binary publication.')
