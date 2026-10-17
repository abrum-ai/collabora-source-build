#!/usr/bin/env python3
"""Exercise real OCI/archive boundaries and publication gates without a registry."""
import copy
import base64
import contextlib
import hashlib
import gzip
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import textwrap
import unittest
from unittest.mock import patch
import urllib.error
import zipfile

spec = importlib.util.spec_from_file_location('q', Path(__file__).with_name('qualify-source.py'))
q = importlib.util.module_from_spec(spec)
spec.loader.exec_module(q)
REPO = 'example/source-build'
COMMIT = 'a' * 40
DIGEST = 'sha256:' + 'b' * 64
SOURCE = 'sha256:' + 'c' * 64
CLOSURE = 'sha256:' + 'd' * 64


def metadata(visibility='private', name='source-build'):
    return {'id': 42, 'name': name, 'visibility': visibility, 'package_type': 'container',
            'owner': {'login': 'example'}, 'repository': {'id': 7, 'full_name': REPO}}


def api(path):
    if path == 'repos/' + REPO:
        return {'id': 7, 'full_name': REPO, 'private': False, 'visibility': 'public', 'owner': {'type': 'Organization'}}
    return metadata()


def oci(root, layers, labels=None):
    """Make actual OCI bytes; tests exercise the real hash/archive reader."""
    (root / 'blobs/sha256').mkdir(parents=True)
    def put(raw, media):
        digest = hashlib.sha256(raw).hexdigest(); (root / 'blobs/sha256' / digest).write_bytes(raw)
        return {'digest': 'sha256:' + digest, 'size': len(raw), 'mediaType': media}
    descriptors, diff_ids = [], []
    for files in layers:
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode='w') as archive:
            for name, raw in files.items():
                entry = tarfile.TarInfo(name); entry.size = len(raw)
                archive.addfile(entry, io.BytesIO(raw))
        raw = data.getvalue(); diff_ids.append('sha256:' + hashlib.sha256(raw).hexdigest())
        descriptors.append(put(gzip.compress(raw, mtime=0), 'application/vnd.oci.image.layer.v1.tar+gzip'))
    config = put(json.dumps({'os': 'linux', 'architecture': 'arm64', 'config': {'Labels': labels or {}},
                             'rootfs': {'type': 'layers', 'diff_ids': diff_ids}}).encode(), 'application/vnd.oci.image.config.v1+json')
    return put(json.dumps({'schemaVersion': 2, 'config': config, 'layers': descriptors}).encode(),
               'application/vnd.oci.image.manifest.v1+json')['digest']


def raw_layer_oci(root, raw, labels=None):
    """Hash/config/descriptor-correct OCI containing exact adversarial TAR bytes."""
    digest = oci(root, [{}], labels)
    def put(data):
        h = hashlib.sha256(data).hexdigest(); (root / 'blobs/sha256' / h).write_bytes(data)
        return {'digest': 'sha256:' + h, 'size': len(data)}
    manifest = json.loads((root / 'blobs/sha256' / digest[7:]).read_bytes())
    config = json.loads((root / 'blobs/sha256' / manifest['config']['digest'][7:]).read_bytes())
    config['rootfs']['diff_ids'] = ['sha256:' + hashlib.sha256(raw).hexdigest()]
    manifest['config'] = {**manifest['config'], **put(json.dumps(config).encode())}
    manifest['layers'] = [{**manifest['layers'][0], **put(gzip.compress(raw, mtime=0))}]
    return put(json.dumps(manifest).encode())['digest']


class SourceClosure(unittest.TestCase):
    def test_new_workflows_admit_only_the_exact_checked_out_default_branch_before_running_code(self):
        for workflow in ['source-qualification.yml.in', 'source-public-seeds.yml.in', 'source-distribution.yml.in']:
            path = Path(__file__).with_name(workflow)
            # The public export renames workflow templates into .github/workflows.
            if not path.exists():
                path = Path(__file__).resolve().parents[2] / '.github/workflows' / workflow.removesuffix('.in')
            content = path.read_text()
            prefix = textwrap.dedent(content.split('        run: |\n', 1)[1].split('          python3 test-source-closure.py', 1)[0])
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp); git = root / 'git'
                git.write_text('#!/bin/sh\nprintf "%s\\n" "' + COMMIT + '"\n'); git.chmod(0o700)
                for ref, commit, expected in [('refs/heads/main', COMMIT, 0),
                                               ('refs/heads/unreviewed', COMMIT, 1),
                                               ('refs/heads/main', 'e' * 40, 1)]:
                    env = {**os.environ, 'PATH': str(root) + os.pathsep + os.environ['PATH'],
                           'RUNNER_ENVIRONMENT': 'github-hosted', 'RUNNER_OS': 'Linux',
                           'GITHUB_EVENT_NAME': 'workflow_dispatch', 'DEFAULT_BRANCH': 'main',
                           'GITHUB_REF': ref, 'GITHUB_SHA': commit}
                    with self.subTest(workflow=workflow, ref=ref, commit=commit):
                        result = subprocess.run(['bash', '-c', prefix], env=env, capture_output=True)
                        self.assertEqual(result.returncode, expected)

    def seed(self, root):
        license_file = root / 'LICENSE'; license_file.write_text('MPL license fixture\n')
        inputs = root / 'inputs.json'; inputs.write_text('{"commit":"' + COMMIT + '"}\n')
        proof = q.seed_layout(REPO, 'source-build-runtime-public', license_file, inputs, 'arm64', root / 'oci')
        return license_file, inputs, proof

    def fixture(self, root):
        (root / 'source-evidence').mkdir()
        (root / 'source-evidence/online-source.tar.zst').write_bytes(b'fixture source archive bytes')
        (root / 'source-evidence/engine-external-sources.tar.zst').write_bytes(b'fixture external source archive bytes')
        (root / 'LICENSE').write_text('License fixture\n')
        q.save(root / 'build-binding.json', {'runtime_digest': DIGEST, 'source_evidence_digest': SOURCE})
        q.save(root / 'runtime-inventory.json', {'layers': ['actual layer inventory fixture']})
        required = ['source-evidence/online-source.tar.zst', 'source-evidence/engine-external-sources.tar.zst']
        q.save(root / 'components.json', {'engine:one': {'kind': 'engine', 'source_archives_required': required}})
        review = {'schema': 'source-closure-review/1', 'closure_digest': CLOSURE,
                  'runtime_digest': DIGEST, 'source_evidence_digest': SOURCE,
                  'components_sha256': q.sha(root / 'components.json'),
                  'inventory_sha256': q.sha(root / 'runtime-inventory.json'),
                  'independent_review': {'reviewer': 'Independent reviewer', 'reference': 'reviewed immutable source reference',
                                         'scope': 'all-delivered-components-and-source-obligations'},
                  'components': {'engine:one': {'license_decision': 'MPL-2.0',
                      'source_files': {name: q.sha(root / name) for name in required},
                      'notice_files': {'LICENSE': q.sha(root / 'LICENSE')}}}}
        return review

    def test_generated_seed_round_trips_as_exactly_two_files_without_base_layers(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); license_file, inputs, p = self.seed(root)
            actual = q.verify_seed(root / 'oci', p['digest'], 'arm64', license_file, inputs)
            self.assertEqual(actual['files'], p['files'])
            self.assertEqual(actual['base_layers'], 0)
            self.assertFalse(actual['runtime_binaries'])

    def test_seed_is_deterministic_and_cannot_target_private_pilot(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); license_file, inputs, p = self.seed(root)
            second = q.seed_layout(REPO, 'source-build-runtime-public', license_file, inputs, 'arm64', root / 'second')
            self.assertEqual(p['digest'], second['digest'])
            with self.assertRaises(ValueError):
                q.seed_layout(REPO, 'source-build', license_file, inputs, 'arm64', root / 'bad')

    def test_seed_rejects_wrong_platform_changed_license_and_corrupt_blob(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); license_file, inputs, p = self.seed(root)
            with self.assertRaises(ValueError):q.verify_seed(root / 'oci', p['digest'], 'amd64', license_file, inputs)
            license_file.write_text('changed')
            with self.assertRaises(ValueError):q.verify_seed(root / 'oci', p['digest'], 'arm64', license_file, inputs)
            (root / 'oci/blobs/sha256' / p['layer_digest'][7:]).write_bytes(b'corrupt')
            with self.assertRaises(ValueError):q.image(root / 'oci', p['digest'], 'arm64')

    def test_source_extraction_rejects_symlinks_and_archive_escape(self):
        for name, kind in [('../../outside', tarfile.REGTYPE), ('link', tarfile.SYMTYPE)]:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp); layer = root / 'layer.tar'
                with tarfile.open(layer, 'w') as archive:
                    entry = tarfile.TarInfo(name); entry.type = kind
                    if kind == tarfile.SYMTYPE:entry.linkname = '/private'
                    archive.addfile(entry, io.BytesIO())
                descriptor = {'digest': 'sha256:' + q.sha(layer), 'size': layer.stat().st_size,
                              'mediaType': 'application/vnd.oci.image.layer.v1.tar'}
                with patch.object(q, 'image', return_value=({'layers': [descriptor]}, {})), patch.object(q, 'blob', return_value=layer):
                    with self.assertRaises(ValueError):q.extract_evidence(root, DIGEST, 'arm64', root / 'out')
                self.assertFalse((root.parent / 'outside').exists())

    def test_paths_cannot_read_outside_evidence_or_follow_symlinks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); (root / 'file').write_text('fixture'); (root / 'link').symlink_to(root / 'file')
            for name in ['../file', '/file', 'a/../../file', 'a\\b', 'link']:
                with self.subTest(name=name), self.assertRaises(ValueError):q.scoped(root, name)
            with self.assertRaises(ValueError):q.file_index(root)

    def test_apk_inventory_keeps_exact_origin_commit_checksum_and_rejects_missing_provenance(self):
        raw = ('C:Q1fixture\nP:busybox\nV:1.37.0-r1\nA:aarch64\nL:GPL-2.0-only\no:busybox\nc:' + COMMIT + '\n').encode()
        p = q.apk_database(raw)[0]
        self.assertEqual(p['aports_commit'], COMMIT)
        self.assertEqual(p['apk_checksum'], 'Q1fixture')
        for key in [b'C:', b'L:', b'o:', b'c:']:
            changed = b'\n'.join(line for line in raw.splitlines() if not line.startswith(key))
            with self.subTest(key=key), self.assertRaises(ValueError):q.apk_database(changed)

    def test_every_component_and_exact_artifact_hashes_are_required(self):
        for mutation in ['component', 'runtime', 'closure', 'inventory', 'source', 'notice', 'license', 'review']:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp); r = self.fixture(root)
                if mutation == 'component':r['components'] = {}
                elif mutation == 'runtime':r['runtime_digest'] = SOURCE
                elif mutation == 'closure':r['closure_digest'] = DIGEST
                elif mutation == 'inventory':r['inventory_sha256'] = '0' * 64
                elif mutation == 'source':r['components']['engine:one']['source_files']['source-evidence/online-source.tar.zst'] = '0' * 64
                elif mutation == 'notice':r['components']['engine:one']['notice_files']['LICENSE'] = '0' * 64
                elif mutation == 'license':r['components']['engine:one']['license_decision'] = 'NOASSERTION'
                else:r['independent_review'] = None
                q.save(root / 'review.json', r)
                with self.assertRaises(ValueError):q.review(root, root / 'review.json', CLOSURE)

    def test_complete_bound_fixture_yields_only_mechanical_review_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); q.save(root / 'review.json', self.fixture(root))
            report = q.review(root, root / 'review.json', CLOSURE)
            self.assertEqual(report['component_count'], 1)
            self.assertEqual(report['mechanical_coverage_and_hash_checks'], 'passed')
            self.assertTrue(report['license_review_is_external'])
            self.assertNotIn('complete_corresponding_source', report)

    def test_empty_or_unsupported_component_inventory_cannot_pass_a_review(self):
        for components in [{}, [], {'engine:one': {'kind': 'unknown'}}]:
            with self.subTest(components=components), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp); r = self.fixture(root)
                q.save(root / 'components.json', components)
                r['components'] = {} if not isinstance(components, dict) else {k: r['components']['engine:one'] for k in components}
                r['components_sha256'] = q.sha(root / 'components.json')
                q.save(root / 'review.json', r)
                with self.assertRaises(ValueError):q.review(root, root / 'review.json', CLOSURE)

    def test_component_metadata_cannot_drop_canonical_source_requirements(self):
        for kind in ['engine', 'apk']:
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp); r = self.fixture(root)
                ident = 'engine:one' if kind == 'engine' else 'apk:busybox@' + COMMIT
                q.save(root / 'components.json', {ident: {'kind': kind}})
                r['components'] = {ident: r['components']['engine:one']}
                r['components_sha256'] = q.sha(root / 'components.json')
                q.save(root / 'review.json', r)
                with self.assertRaises(ValueError):q.review(root, root / 'review.json', CLOSURE)

    def apk_output(self, root):
        output = root / 'output'; (output / 'package/src').mkdir(parents=True)
        (output / 'packages.txt').write_text('busybox-1.37-r1.apk\n')
        origin = {'origin': 'busybox', 'commit': COMMIT,
                  'packages': [{'name': 'busybox', 'version': '1.37-r1'}]}
        q.save(root / 'origins.json', [origin])
        recipe = root / 'recipe.tar'
        self.source_tar(recipe, 'main/busybox/APKBUILD', b'pkgname=busybox\n')
        self.source_tar(output / 'package/src/busybox.src.tar.gz', 'busybox/APKBUILD', b'pkgname=busybox\n')
        destination = root / 'evidence'; destination.mkdir()
        return output, recipe, destination

    def source_tar(self, path, name, raw, duplicate=False):
        with tarfile.open(path, 'w:gz' if path.name.endswith('.gz') else 'w') as archive:
            for _ in range(2 if duplicate else 1):
                entry = tarfile.TarInfo(name); entry.size = len(raw)
                archive.addfile(entry, io.BytesIO(raw))

    def collect_apk(self, root, output, recipe, destination):
        return q.collect_apk_source(root / 'origins.json', 'busybox', COMMIT, output, recipe, destination)

    def test_apk_source_output_copies_only_the_exact_pinned_recipe_archive_and_package_list(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); output, recipe, destination = self.apk_output(root)
            result = self.collect_apk(root, output, recipe, destination)
            self.assertEqual(len(result['files']), 3)
            self.assertEqual(result['files'], q.file_index(destination))
            self.assertEqual((destination / ('busybox-' + COMMIT + '.src.tar.gz')).read_bytes(),
                             (output / 'package/src/busybox.src.tar.gz').read_bytes())
            with self.assertRaises(ValueError):self.collect_apk(root, output, recipe, destination)

    def test_apk_fetcher_cannot_read_or_copy_a_symlinked_package_list(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); output, recipe, destination = self.apk_output(root)
            outside = root / 'outside'; outside.write_text('busybox-1.37-r1.apk SYNTHETIC_OUTSIDE_MARKER\n')
            listing = output / 'packages.txt'; listing.unlink(); listing.symlink_to(outside)
            original_read = Path.read_text
            def guarded_read(path, *args, **kwargs):
                if path.resolve() == outside.resolve():raise AssertionError('Read escaped the container output')
                return original_read(path, *args, **kwargs)
            with patch.object(Path, 'read_text', guarded_read), self.assertRaises(ValueError):
                self.collect_apk(root, output, recipe, destination)
            self.assertEqual(list(destination.iterdir()), [])

    def test_apk_output_rejects_escaped_archive_directories_and_symlinked_archives(self):
        for kind in ['directory', 'archive']:
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp); output, recipe, destination = self.apk_output(root)
                archive = output / 'package/src/busybox.src.tar.gz'; outside = root / 'outside'; outside.mkdir()
                archive.rename(outside / archive.name)
                if kind == 'directory':
                    archive.parent.rmdir(); archive.parent.symlink_to(outside, target_is_directory=True)
                else:archive.symlink_to(outside / archive.name)
                with self.assertRaises(ValueError):self.collect_apk(root, output, recipe, destination)
                self.assertEqual(list(destination.iterdir()), [])

    def test_apk_source_output_rejects_rewritten_or_ambiguous_apkbuild_and_wrong_package_version(self):
        for change in ['recipe', 'duplicate', 'version']:
            with self.subTest(change=change), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp); output, recipe, destination = self.apk_output(root)
                archive = output / 'package/src/busybox.src.tar.gz'
                if change == 'recipe':self.source_tar(archive, 'busybox/APKBUILD', b'rewritten recipe\n')
                elif change == 'duplicate':self.source_tar(archive, 'busybox/APKBUILD', b'pkgname=busybox\n', duplicate=True)
                else:(output / 'packages.txt').write_text('busybox-older.apk\n')
                with self.assertRaises(ValueError):self.collect_apk(root, output, recipe, destination)
                self.assertEqual(list(destination.iterdir()), [])

    def test_metadata_file_is_not_a_component_source_and_apk_archive_cannot_be_omitted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); r = self.fixture(root)
            r['components']['engine:one']['source_files'] = {'components.json': q.sha(root / 'components.json')}
            q.save(root / 'review.json', r)
            with self.assertRaises(ValueError):q.review(root, root / 'review.json', CLOSURE)
            r = self.fixture_existing(root)
            q.save(root / 'components.json', {'engine:one': {'kind': 'apk', 'source_archives_required': ['apk-sources/busybox-' + COMMIT + '.src.tar.gz']}})
            r['components_sha256'] = q.sha(root / 'components.json'); q.save(root / 'review.json', r)
            with self.assertRaises(ValueError):q.review(root, root / 'review.json', CLOSURE)

    def fixture_existing(self, root):
        r = json.loads((root / 'review.json').read_text())
        r['components']['engine:one']['source_files'] = {'source-evidence/online-source.tar.zst': q.sha(root / 'source-evidence/online-source.tar.zst')}
        return r

    def test_real_nested_notice_bytes_are_checked_without_extracting_source_tree(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); source = root / 'source.tar.gz'
            with tarfile.open(source, 'w:gz') as archive:
                data = b'actual license fixture\n'; entry = tarfile.TarInfo('project/COPYING'); entry.size = len(data)
                archive.addfile(entry, io.BytesIO(data))
            self.assertEqual(q.notice_bytes(root, 'source.tar.gz::project/COPYING'), data)
            with self.assertRaises((ValueError, KeyError)):q.notice_bytes(root, 'source.tar.gz::../COPYING')

    def test_package_seed_only_follows_actual_404_at_separate_new_target(self):
        def missing(path):
            if path == 'repos/' + REPO:return api(path)
            raise urllib.error.HTTPError('https://api.github.com/' + path, 404, 'missing', {}, None)
        with patch.object(q, 'github', side_effect=missing):
            self.assertIsNone(q.package(REPO, 'private', 'source-build-runtime-public', allow_seed=True))
            with self.assertRaises(urllib.error.HTTPError):q.package(REPO, 'private', 'source-build', allow_seed=True)

    def test_auth_errors_never_admit_a_seed_and_public_pilot_never_admits_private_write(self):
        for code in [301, 401, 403, 429, 503]:
            def denied(path):
                if path == 'repos/' + REPO:return api(path)
                raise urllib.error.HTTPError('https://api.github.com/' + path, code, 'denied', {}, None)
            with self.subTest(code=code), patch.object(q, 'github', side_effect=denied):
                with self.assertRaises(urllib.error.HTTPError):q.package(REPO, 'private', 'source-build-runtime-public', allow_seed=True)
        with patch.object(q, 'github', side_effect=lambda p:api(p) if p == 'repos/' + REPO else metadata('public')):
            with self.assertRaises(ValueError):q.package(REPO, 'private')

    def test_package_identity_and_repository_binding_cannot_be_substituted(self):
        for change in [{'id': 43}, {'repository': {'id': 8, 'full_name': REPO}}, {'owner': {'login': 'foreign'}}, {'visibility': 'internal'}]:
            def changed(path):
                if path == 'repos/' + REPO:return api(path)
                return {**metadata(), **change}
            with self.subTest(change=change), patch.object(q, 'github', side_effect=changed):
                with self.assertRaises(ValueError):q.package(REPO, 'private', expected_id=42)

    def test_publication_never_overwrites_a_tag_with_another_digest(self):
        with patch.object(q, 'package', return_value={'collection': 'orgs'}), patch.object(q, 'github', return_value=[{'name': SOURCE, 'metadata': {'container': {'tags': ['qualified']}}}]):
            with self.assertRaises(ValueError):q.tag_state(REPO, 'source-build-runtime-public', 'public', 42, 'qualified', DIGEST)
        with patch.object(q, 'package', return_value={'collection': 'orgs'}), patch.object(q, 'github', return_value=[{'name': DIGEST, 'metadata': {'container': {'tags': ['qualified']}}}]):
            self.assertEqual(q.tag_state(REPO, 'source-build-runtime-public', 'public', 42, 'qualified', DIGEST)['state'], 'already-present')

    def test_failed_or_foreign_build_cannot_authorize_artifact_qualification(self):
        run = {'id': 9, 'repository': {'id': 7}, 'head_repository': {'id': 7}, 'head_sha': COMMIT,
               'event': 'workflow_dispatch', 'path': '.github/workflows/source-build.yml',
               'display_title': 'Full Collabora source build (arm64)', 'status': 'completed', 'conclusion': 'success'}
        for change in [{'conclusion': 'failure'}, {'status': 'in_progress'}, {'head_sha': 'e' * 40},
                       {'head_repository': {'id': 8}}, {'event': 'pull_request'}, {'path': 'other.yml'}]:
            with self.subTest(change=change), patch.object(q, 'package', return_value={'repository_id': 7}), patch.object(q, 'github', return_value={**run, **change}):
                with self.assertRaises(ValueError):q.bind(REPO, 9, COMMIT, 'arm64', DIGEST, SOURCE)

    def inventory_fixture(self, root, bad_sum=False):
        def db(version, commit):
            return ('C:Q1fixture\nP:busybox\nV:'+version+'\nA:aarch64\nL:GPL-2.0-only\no:busybox\nc:'+commit+'\n').encode()
        runtime = oci(root / 'runtime', [
            {'lib/apk/db/installed': db('1.36-r0', 'e' * 40)},
            {'lib/apk/db/installed': db('1.37-r1', COMMIT), 'usr/share/fonts/family/font.ttf': b'font fixture'}],
            {'org.opencontainers.image.source': 'https://github.com/' + REPO, 'org.opencontainers.image.revision': COMMIT})
        recipe = {'Dockerfile': b'FROM source', 'build-source.sh': b'build from source',
                  'upstream.lock.json': json.dumps({'commit': COMMIT}).encode()}
        files = {**recipe, 'notices/upstream-commit.txt': COMMIT.encode(),
                 'notices/collabora-online-sbom.spdx.json': json.dumps({'packages': [{'SPDXID': 'SPDXRef-engine', 'licenseDeclared': 'MPL-2.0'}]}).encode(),
                 'online-source.tar.zst': b'compressed source fixture', 'engine-external-sources.tar.zst': b'compressed external source fixture'}
        lines = [hashlib.sha256(raw).hexdigest()+'  ./'+name for name, raw in files.items()]
        files['SHA256SUMS'] = ('\n'.join(lines)+'\n').encode()
        if bad_sum:files['Dockerfile'] = b'changed after checksum'
        source = oci(root / 'source', [files])
        binding = {'runtime_digest': runtime, 'source_evidence_digest': source, 'architecture': 'arm64',
                   'repository': REPO, 'build_commit': COMMIT,
                   'recipe_files_sha256': {name: hashlib.sha256(raw).hexdigest() for name, raw in recipe.items()}}
        return binding

    def test_inventory_includes_old_packages_in_lower_layers_and_all_font_directories(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); binding = self.inventory_fixture(root)
            q.inventory(binding, root / 'runtime', root / 'source', root / 'evidence')
            origins = json.loads((root / 'evidence/apk-origins.json').read_text())
            self.assertEqual({p['version'] for origin in origins for p in origin['packages']}, {'1.36-r0', '1.37-r1'})
            components = json.loads((root / 'evidence/components.json').read_text())
            self.assertIn('font-directory:usr/share/fonts/family', components)
            self.assertEqual(len(components), 4)

    def test_inventory_rejects_changed_source_checksums_and_recipe_from_another_build(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); binding = self.inventory_fixture(root, bad_sum=True)
            with self.assertRaises(ValueError):q.inventory(binding, root / 'runtime', root / 'source', root / 'evidence')

    def test_index_cannot_hide_a_second_uninventoried_runtime_platform(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); license_file, inputs, seed = self.seed(root)
            layout = root / 'oci'; manifest = layout / 'blobs/sha256' / seed['digest'][7:]
            descriptor = {'digest': seed['digest'], 'size': manifest.stat().st_size,
                          'mediaType': 'application/vnd.oci.image.manifest.v1+json'}
            index = {'schemaVersion': 2, 'manifests': [
                {**descriptor, 'platform': {'os': 'linux', 'architecture': 'arm64'}},
                {**descriptor, 'platform': {'os': 'linux', 'architecture': 'amd64'}}]}
            raw = json.dumps(index).encode(); digest = 'sha256:' + hashlib.sha256(raw).hexdigest()
            (layout / 'blobs/sha256' / digest[7:]).write_bytes(raw)
            with self.assertRaises(ValueError):q.image(layout, digest, 'arm64')
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); binding = self.inventory_fixture(root)
            binding['recipe_files_sha256']['Dockerfile'] = '0' * 64
            with self.assertRaises(ValueError):q.inventory(binding, root / 'runtime', root / 'source', root / 'evidence')

    def inspection_fixture(self, root):
        binding = self.inventory_fixture(root)
        binding.update({'build_run_id': 9, 'package': {'repository_id': 7}})
        evidence = root / 'evidence'
        q.inventory(binding, root / 'runtime', root / 'source', evidence)
        q.save(evidence / 'apk-source-checksums.json', {'fixture.src.tar.gz': 'a' * 64})
        (evidence / 'source-evidence/NOTICE').write_bytes(b'actual fixture notice\n::add-mask::example\n\x1b[2J')
        context = {'run_id': 12, 'run_attempt': 2, 'job_id': 34, 'workflow_commit': COMMIT}
        request = {'schema': 'source-inspection-request/1', 'closure_digest': CLOSURE,
                   'references': ['source-evidence/NOTICE']}
        return binding, evidence, context, request

    def inspection_log(self, root):
        binding, evidence, context, request = self.inspection_fixture(root)
        manifest, documents = q.inspection_documents(evidence, binding, CLOSURE, context, request)
        stream = io.StringIO(); q.emit_inspection(manifest, documents, stream)
        return stream.getvalue(), {**context, 'closure_digest': CLOSURE}, evidence

    def test_inspection_recovers_complete_real_inventories_file_hashes_and_safe_notice_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            log, expected, evidence = self.inspection_log(Path(tmp))
            self.assertNotIn('::add-mask::example', log)
            self.assertNotIn('\x1b', log)
            timestamped = '\n'.join('2026-10-17T07:00:00.0000000Z ' + line for line in log.splitlines())
            manifest, documents = q.decode_inspection(timestamped, expected)
            data = dict(documents)
            self.assertFalse(manifest['legal_review_performed'])
            self.assertEqual(data['runtime-inventory.json'], (evidence / 'runtime-inventory.json').read_bytes())
            self.assertEqual(data['components.json'], (evidence / 'components.json').read_bytes())
            self.assertEqual(data['source-evidence/NOTICE'], (evidence / 'source-evidence/NOTICE').read_bytes())
            index = json.loads(data['@complete-file-index'])
            actual = {p.relative_to(evidence).as_posix(): {'size': p.stat().st_size, 'sha256': q.sha(p)}
                      for p in evidence.rglob('*') if p.is_file()}
            self.assertEqual(index, actual)
            self.assertEqual(len(documents), 9)

    def test_inspection_reads_real_nested_zip_in_tar_without_extracting_a_tree(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); (root / 'source-evidence').mkdir()
            inner = io.BytesIO()
            with zipfile.ZipFile(inner, 'w') as archive:
                archive.writestr('project/COPYING', b'original nested license bytes\n')
            path = root / 'source-evidence/sources.tar.gz'
            with tarfile.open(path, 'w:gz') as archive:
                entry = tarfile.TarInfo('external.zip'); entry.size = len(inner.getvalue())
                archive.addfile(entry, io.BytesIO(inner.getvalue()))
            raw = q.inspection_reference(root, 'source-evidence/sources.tar.gz::external.zip::project/COPYING')
            self.assertEqual(raw, b'original nested license bytes\n')
            listing = json.loads(q.inspection_reference(root, 'source-evidence/sources.tar.gz::external.zip::@members'))
            self.assertTrue(listing['complete'])
            self.assertEqual(listing['members'], [{'path': 'project/COPYING', 'kind': 'file',
                                                  'size': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}])
            self.assertFalse((root / 'project').exists())

    def test_inspection_compressed_stream_trailers_and_decompression_budget_are_checked(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'source.tar.gz'
            with tarfile.open(path, 'w:gz') as archive:
                entry = tarfile.TarInfo('COPYING'); entry.size = 20000
                archive.addfile(entry, io.BytesIO(b'x' * entry.size))
            complete = path.read_bytes()
            self.assertEqual(q.inspection_member(path, 'COPYING', 30000), b'x' * 20000)
            for raw in [complete[:-8], complete[:-4], complete[:-8] + bytes(8)]:
                path.write_bytes(raw)
                with self.assertRaises((ValueError, OSError, EOFError)):
                    q.inspection_member(path, 'COPYING', 30000)
            path.write_bytes(complete)
            with patch.object(q, 'INSPECTION_ARCHIVE_BUDGET', 1024):
                with self.assertRaises(ValueError):q.inspection_member(path, 'COPYING', 30000)

    def test_inspection_large_notice_chunks_and_header_limit_are_complete_or_emit_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            binding, evidence, context, request = self.inspection_fixture(Path(tmp))
            raw = b'original notice\n' * 4000
            (evidence / 'source-evidence/NOTICE').write_bytes(raw)
            manifest, documents = q.inspection_documents(evidence, binding, CLOSURE, context, request)
            stream = io.StringIO(); q.emit_inspection(manifest, documents, stream)
            decoded, contents = q.decode_inspection(stream.getvalue(), {**context, 'closure_digest': CLOSURE})
            self.assertEqual(dict(contents)['source-evidence/NOTICE'], raw)
            self.assertGreater(decoded['documents'][-1]['chunks'], 1)
            manifest['ci']['unbounded'] = 'x' * 40000
            stream = io.StringIO()
            with self.assertRaises(ValueError):q.emit_inspection(manifest, documents, stream)
            self.assertEqual(stream.getvalue(), '')

    def test_inspection_reads_and_rejects_incomplete_bzip2_and_xz_streams(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'source.tar'
            with tarfile.open(path, 'w') as archive:
                entry = tarfile.TarInfo('COPYING'); entry.size = 1000
                archive.addfile(entry, io.BytesIO(b'x' * 1000))
            original = path.read_bytes()
            for compressor in [q.bz2.compress, q.lzma.compress]:
                with self.subTest(compressor=compressor.__module__):
                    raw = compressor(original); path.write_bytes(raw)
                    self.assertEqual(q.inspection_member(path, 'COPYING', 2000), b'x' * 1000)
                    path.write_bytes(raw[:-8])
                    with self.assertRaises((ValueError, OSError, EOFError)):
                        q.inspection_member(path, 'COPYING', 2000)

    def test_inspection_rejects_host_paths_controls_and_all_symlink_ancestors(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); binding, evidence, context, request = self.inspection_fixture(root)
            outside = root / 'host-secret'; outside.write_text('synthetic outside marker')
            (evidence / 'source-evidence/outside').symlink_to(outside)
            (evidence / 'source-evidence/inside').symlink_to(evidence / 'source-evidence', target_is_directory=True)
            for reference in ['/host-secret', '../host-secret', 'source-evidence/../../host-secret',
                              'source-evidence/NOTICE\n::error::bad', 'source-evidence/./NOTICE',
                              'source-evidence/outside', 'source-evidence/inside/NOTICE',
                              'source-evidence/a.tar::../COPYING']:
                with self.subTest(reference=reference), self.assertRaises(ValueError):
                    q.inspection_reference(evidence, reference)
            with self.assertRaises(ValueError):q.inspection_documents(evidence, binding, CLOSURE, context, request)

    def test_inspection_rejects_duplicate_regular_or_linked_tar_members(self):
        for mode in ['duplicate', 'symlink', 'hardlink']:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / 'source.tar.gz'
                with tarfile.open(path, 'w:gz') as archive:
                    entry = tarfile.TarInfo('COPYING'); entry.size = 4
                    if mode != 'duplicate':
                        entry.type = tarfile.SYMTYPE if mode == 'symlink' else tarfile.LNKTYPE
                        entry.size = 0; entry.linkname = '/host-secret'
                    archive.addfile(entry, io.BytesIO(b'text'))
                    if mode == 'duplicate':
                        entry = tarfile.TarInfo('./COPYING'); entry.size = 5
                        archive.addfile(entry, io.BytesIO(b'other'))
                with self.assertRaises(ValueError):q.inspection_member(path, 'COPYING', 100)
                if mode == 'duplicate':
                    with self.assertRaises(ValueError):q.inspection_member(path, None, 1000)

    def test_inspection_rejects_duplicate_or_symlink_zip_members_and_corrupt_crc(self):
        for mode in ['duplicate', 'symlink', 'crc']:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / 'sources.zip'
                with zipfile.ZipFile(path, 'w', compression=zipfile.ZIP_STORED) as archive:
                    entry = zipfile.ZipInfo('COPYING')
                    if mode == 'symlink':entry.create_system = 3; entry.external_attr = 0o120777 << 16
                    archive.writestr(entry, b'license text')
                    if mode == 'duplicate':archive.writestr('./COPYING', b'other')
                if mode == 'crc':
                    raw = bytearray(path.read_bytes()); raw[30 + len('COPYING')] ^= 1; path.write_bytes(raw)
                with self.assertRaises((ValueError, zipfile.BadZipFile)):
                    q.inspection_member(path, 'COPYING', 100)

    def test_inspection_rejects_missing_truncated_and_oversized_archive_members(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'source.tar'
            entry = tarfile.TarInfo('COPYING'); entry.size = 4096
            path.write_bytes(entry.tobuf() + b'tiny')
            with self.assertRaises((ValueError, tarfile.TarError)):
                q.inspection_member(path, 'COPYING', 5000)
            with tarfile.open(path, 'w') as archive:
                entry = tarfile.TarInfo('COPYING'); entry.size = 101
                archive.addfile(entry, io.BytesIO(b'x' * 101))
            with self.assertRaises(ValueError):q.inspection_member(path, 'COPYING', 100)
            with self.assertRaises(ValueError):q.inspection_member(path, 'missing', 200)

    def test_inspection_rejects_changed_binding_missing_inventory_duplicate_json_and_request_limits(self):
        for mutation in ['binding', 'missing', 'duplicate-json', 'candidate', 'duplicate-ref', 'many-refs', 'unknown-field']:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                binding, evidence, context, request = self.inspection_fixture(Path(tmp))
                if mutation == 'binding':binding = {**binding, 'build_commit': 'e' * 40}
                elif mutation == 'missing':(evidence / 'components.json').unlink()
                elif mutation == 'duplicate-json':(evidence / 'components.json').write_text('{"x":1,"x":2}')
                elif mutation == 'candidate':request['closure_digest'] = DIGEST
                elif mutation == 'duplicate-ref':request['references'] *= 2
                elif mutation == 'many-refs':request['references'] = ['source-evidence/' + str(i) for i in range(33)]
                else:request['review_approved'] = True
                with self.assertRaises(ValueError):q.inspection_documents(evidence, binding, CLOSURE, context, request)

    def test_inspection_log_rejects_truncation_tamper_reordering_duplicate_and_wrong_ci_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            log, expected, _ = self.inspection_log(Path(tmp))
            lines = log.splitlines()
            variants = [lines[1:], lines[:-1], lines[:1] + lines[2:], lines[:2] + lines[1:],
                        lines[:1] + [lines[2], lines[1]] + lines[3:], lines + lines[-1:]]
            changed = json.loads(lines[1][len(q.INSPECTION_PREFIX):]); changed['base64'] = base64.b64encode(b'wrong bytes').decode()
            variants.append([lines[0], q.INSPECTION_PREFIX + json.dumps(changed), *lines[2:]])
            for index, variant in enumerate(variants):
                with self.subTest(index=index), self.assertRaises(ValueError):q.decode_inspection('\n'.join(variant), expected)
            for key in expected:
                actual = {**expected, key: 'wrong' if isinstance(expected[key], str) else 999}
                with self.subTest(key=key), self.assertRaises(ValueError):q.decode_inspection(log, actual)

    def test_inspection_malformed_frames_and_incomplete_cli_log_create_no_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); log, expected, _ = self.inspection_log(root)
            for record in ['[]', 'null', '"text"', '{"x":1,"x":2}', '{"event":NaN}', '[' * 2000]:
                with self.subTest(record=record[:30]), self.assertRaises(ValueError):
                    q.decode_inspection(q.INSPECTION_PREFIX + record, expected)
            path = root / 'bad.log'; path.write_text('\n'.join(log.splitlines()[:-1]))
            argv = ['qualify-source.py', 'decode-inspection', '--log-file', str(path), '--destination', str(root / 'output')]
            for key, value in expected.items():argv += ['--' + key.replace('_', '-'), str(value)]
            with patch.object(q.sys, 'argv', argv), self.assertRaises(ValueError):q.main()
            self.assertFalse((root / 'output').exists())

    def test_inspection_context_uses_actual_run_attempt_and_unique_job_api_binding(self):
        binding = {'repository': REPO, 'package': {'repository_id': 7}}
        env = {'GITHUB_REPOSITORY': REPO, 'GITHUB_EVENT_NAME': 'workflow_dispatch',
               'RUNNER_ENVIRONMENT': 'github-hosted', 'RUNNER_OS': 'Linux', 'GITHUB_JOB': 'inspect',
               'GITHUB_SHA': COMMIT, 'GITHUB_WORKFLOW_SHA': COMMIT, 'GITHUB_RUN_ID': '12',
               'GITHUB_RUN_ATTEMPT': '2', 'GITHUB_REF': 'refs/heads/main'}
        run = {'id': 12, 'run_attempt': 2, 'repository': {'id': 7}, 'head_repository': {'id': 7},
               'event': 'workflow_dispatch', 'head_sha': COMMIT, 'head_branch': 'main',
               'path': '.github/workflows/source-qualification.yml'}
        job = {'id': 34, 'name': 'inspect', 'run_id': 12, 'head_sha': COMMIT}
        def response(path):
            if path == 'repos/' + REPO:return {**api(path), 'default_branch': 'main'}
            if path.endswith('/attempts/2'):return run
            self.assertIn('/attempts/2/jobs?', path); return {'jobs': [job]}
        with patch.object(q, 'github', side_effect=response):
            actual = q.inspection_context(binding, env)
            self.assertEqual((actual['run_id'], actual['run_attempt'], actual['job_id']), (12, 2, 34))
            for key, value in [('GITHUB_REF', 'refs/heads/feature'), ('GITHUB_WORKFLOW_SHA', 'e' * 40),
                               ('GITHUB_JOB', 'collect'), ('GITHUB_RUN_ATTEMPT', '0')]:
                with self.subTest(key=key), self.assertRaises(ValueError):q.inspection_context(binding, {**env, key: value})
            for key, value in [('head_sha', 'e' * 40), ('run_attempt', 1), ('path', 'other.yml'), ('repository', {'id': 8})]:
                previous = run[key]; run[key] = value
                with self.subTest(key=key), self.assertRaises(ValueError):q.inspection_context(binding, env)
                run[key] = previous
        with patch.object(q, 'github', side_effect=lambda p: {**api(p), 'default_branch': 'main'} if p == 'repos/' + REPO
                          else run if p.endswith('/attempts/2') else {'jobs': [job, job]}):
            with self.assertRaises(ValueError):q.inspection_context(binding, env)

    def test_inspection_cli_fresh_binding_and_oci_validation_precede_any_log_output(self):
        for mutation in ['none', 'binding', 'blob', 'budget']:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp); binding, evidence, context, request = self.inspection_fixture(root)
                files = {p.relative_to(evidence).as_posix(): p.read_bytes() for p in evidence.rglob('*') if p.is_file()}
                digest = oci(root / 'closure', [files])
                argv = ['qualify-source.py', 'inspect', '--repository', REPO, '--build-run', '9',
                        '--build-commit', COMMIT, '--arch', 'arm64', '--runtime-digest', binding['runtime_digest'],
                        '--source-digest', binding['source_evidence_digest'], '--closure-digest', digest,
                        '--layout', str(root / 'closure'), '--destination', str(root / 'decoded')]
                if mutation == 'binding':binding = {**binding, 'build_commit': 'e' * 40}
                if mutation == 'blob':(root / 'closure/blobs/sha256' / digest[7:]).write_text('changed')
                stream = io.StringIO()
                with patch.object(q, 'bind', return_value=binding) as fresh, patch.object(q, 'inspection_context', return_value=context), \
                     patch.object(q.sys, 'argv', argv), contextlib.redirect_stdout(stream), \
                     patch.object(q, 'INSPECTION_TOTAL', 8 if mutation == 'budget' else q.INSPECTION_TOTAL):
                    if mutation == 'none':q.main()
                    else:
                        with self.assertRaises(ValueError):q.main()
                    fresh.assert_called_once_with(REPO, 9, COMMIT, 'arm64', binding['runtime_digest'], binding['source_evidence_digest'])
                if mutation == 'none':self.assertIn(q.INSPECTION_PREFIX, stream.getvalue())
                else:self.assertEqual(stream.getvalue(), '')

    def test_inspection_offline_decoder_cli_reconstructs_only_numbered_files_without_credentials(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); log, expected, _ = self.inspection_log(root)
            path = root / 'ci.log'; path.write_text(log)
            argv = ['qualify-source.py', 'decode-inspection', '--log-file', str(path), '--destination', str(root / 'output')]
            for key, value in expected.items():argv += ['--' + key.replace('_', '-'), str(value)]
            with patch.object(q.sys, 'argv', argv), patch.object(q, 'github', side_effect=AssertionError('Offline decoder must not access GitHub')):
                q.main()
            manifest = json.loads((root / 'output/manifest.json').read_text())
            notice = next(i for i, d in enumerate(manifest['documents']) if d['reference'] == 'source-evidence/NOTICE')
            self.assertIn(b'::add-mask::example', (root / 'output' / (str(notice).zfill(4) + '.bin')).read_bytes())
            self.assertFalse((root / 'output/source-evidence').exists())

    def test_inspection_workflow_is_read_only_and_has_an_independent_pending_slot(self):
        path = Path(__file__).with_name('source-qualification.yml.in')
        if not path.exists():path = Path(__file__).resolve().parents[2] / '.github/workflows/source-qualification.yml'
        text = path.read_text(); reader = text.split('\n  inspect:\n', 1)[1]
        self.assertIn("inputs.operation == 'inspect' && format('source-closure-inspection-{0}', github.run_id) || 'full-source-build'", text)
        self.assertIn('      contents: read\n      actions: read\n      packages: read\n', reader)
        for forbidden in ['packages: write', '--dest-authfile', 'docker build', 'docker push', 'upload-artifact', 'actions/cache', 'PAT']:
            self.assertNotIn(forbidden, reader)
        self.assertLess(reader.index('qualify-source.py bind'), reader.index('skopeo copy'))
        prefix = textwrap.dedent(reader.split('        run: |\n', 1)[1].split('          python3 test-source-closure.py', 1)[0])
        with tempfile.TemporaryDirectory() as tmp:
            git = Path(tmp) / 'git'; git.write_text('#!/bin/sh\nprintf "%s\\n" "' + COMMIT + '"\n'); git.chmod(0o700)
            env = {**os.environ, 'PATH': tmp + os.pathsep + os.environ['PATH'], 'RUNNER_ENVIRONMENT': 'github-hosted',
                   'RUNNER_OS': 'Linux', 'GITHUB_EVENT_NAME': 'workflow_dispatch', 'GITHUB_REF': 'refs/heads/main',
                   'DEFAULT_BRANCH': 'main', 'GITHUB_SHA': COMMIT, 'GITHUB_WORKFLOW_SHA': COMMIT}
            self.assertEqual(subprocess.run(['bash', '-c', prefix], env=env).returncode, 0)
            for key, value in [('GITHUB_REF', 'refs/heads/feature'), ('GITHUB_SHA', 'e' * 40), ('GITHUB_WORKFLOW_SHA', 'e' * 40)]:
                with self.subTest(key=key):self.assertNotEqual(subprocess.run(['bash', '-c', prefix], env={**env, key: value}).returncode, 0)

    def tar_bytes(self, name='COPYING', raw=b'original notice', format=tarfile.PAX_FORMAT):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode='w', format=format) as archive:
            entry = tarfile.TarInfo(name); entry.size = len(raw)
            archive.addfile(entry, io.BytesIO(raw))
        return stream.getvalue()

    def test_shared_tar_boundary_rejects_second_archives_duplicates_and_junk_across_codecs(self):
        first = self.tar_bytes()
        for encode in [lambda b: b, gzip.compress, q.bz2.compress, q.lzma.compress]:
            for tail in [self.tar_bytes('SECOND-COPYING'), self.tar_bytes('COPYING', b'contradictory notice'),
                         b'nonzero tail', bytes(512) + b'nonzero after padding' + bytes(491)]:
                with self.subTest(codec=encode.__module__, tail=tail[:10]), tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp); (root / 'source-evidence').mkdir()
                    path = root / 'source-evidence/source.tar'; path.write_bytes(encode(first + tail))
                    for consume in [lambda: next(q.members(path)), lambda: q.tar_member_bytes(path, 'COPYING'),
                                    lambda: q.notice_bytes(root, 'source-evidence/source.tar::COPYING'),
                                    lambda: q.inspection_member(path, 'COPYING', 1000),
                                    lambda: q.inspection_member(path, None, 100000)]:
                        with self.assertRaises(ValueError):consume()

    def test_shared_tar_boundary_checks_all_concatenated_compression_frames_and_trailers(self):
        first, second = self.tar_bytes(), self.tar_bytes('SECOND-COPYING')
        for encode in [gzip.compress, q.bz2.compress, q.lzma.compress]:
            with self.subTest(codec=encode.__module__), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / 'archive'
                # Splitting ONE valid TAR between frames remains valid.
                path.write_bytes(encode(first[:1013]) + encode(first[1013:]))
                self.assertEqual(q.tar_member_bytes(path, 'COPYING'), b'original notice')
                for raw in [encode(first) + encode(second), encode(first) + b'nonframe junk', encode(first)[:-1]]:
                    path.write_bytes(raw)
                    with self.assertRaises(ValueError):list(q.members(path))
                corrupted = bytearray(encode(first)); corrupted[-8] ^= 255; path.write_bytes(corrupted)
                with self.assertRaises(ValueError):list(q.members(path))

    def test_shared_tar_boundary_preserves_canonical_padding_empty_gnu_and_pax_archives(self):
        for raw in [self.tar_bytes(), self.tar_bytes() + bytes(65536), bytes(1024),
                    self.tar_bytes('pax/' + 'long-path-' * 30),
                    self.tar_bytes('gnu/' + 'long-path-' * 30, format=tarfile.GNU_FORMAT)]:
            with self.subTest(size=len(raw)), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / 'source.tar'; path.write_bytes(raw)
                entries = list(q.members(path))
                self.assertEqual(len(entries), 0 if raw == bytes(1024) else 1)
                if entries:self.assertEqual(q.tar_member_bytes(path, entries[0][0]), b'original notice')

    def test_shared_tar_boundary_rejects_missing_end_block_partial_padding_and_member_junk(self):
        raw = self.tar_bytes()
        for broken in [raw[:1024], raw[:1536], raw[:2047], raw + bytes(1),
                       raw[:512 + len(b'original notice')] + b'X' + raw[513 + len(b'original notice'):]]:
            with self.subTest(size=len(broken)), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / 'source.tar'; path.write_bytes(broken)
                with self.assertRaises(ValueError):next(q.members(path))

    def test_shared_tar_boundary_is_used_by_real_hash_verified_oci_extraction_and_runtime_inventory(self):
        bad = self.tar_bytes() + self.tar_bytes('SECOND-COPYING')
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); digest = raw_layer_oci(root / 'layer', bad)
            q.image(root / 'layer', digest, 'arm64')
            with self.assertRaises(ValueError):q.extract_evidence(root / 'layer', digest, 'arm64', root / 'out')
            self.assertEqual(list((root / 'out').rglob('*')), [])
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); binding = self.inventory_fixture(root)
            labels = {'org.opencontainers.image.source': 'https://github.com/' + REPO,
                      'org.opencontainers.image.revision': COMMIT}
            binding['runtime_digest'] = raw_layer_oci(root / 'bad-runtime', bad, labels)
            with self.assertRaises(ValueError):q.inventory(binding, root / 'bad-runtime', root / 'source', root / 'out')
            self.assertFalse((root / 'out/runtime-inventory.json').exists())

    def test_shared_tar_boundary_rejects_nested_notice_and_inspection_before_any_frame(self):
        for duplicate in [False, True]:
            with self.subTest(duplicate=duplicate), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp); binding, evidence, context, request = self.inspection_fixture(root)
                tail = self.tar_bytes('COPYING' if duplicate else 'SECOND-COPYING', b'second notice')
                (evidence / 'source-evidence/bad.tar').write_bytes(self.tar_bytes() + tail)
                request['references'] = ['source-evidence/bad.tar::@members']
                stream = io.StringIO()
                with self.assertRaises(ValueError):
                    manifest, documents = q.inspection_documents(evidence, binding, CLOSURE, context, request)
                    q.emit_inspection(manifest, documents, stream)
                self.assertEqual(stream.getvalue(), '')
                outer = self.tar_bytes('inner.tar', self.tar_bytes() + tail)
                (evidence / 'source-evidence/outer.tar').write_bytes(outer)
                with self.assertRaises(ValueError):q.notice_bytes(evidence, 'source-evidence/outer.tar::inner.tar::COPYING')

    def test_shared_tar_metadata_and_decoded_end_padding_budgets_fail_before_any_yield(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'source.tar'; raw = self.tar_bytes(); path.write_bytes(raw)
            for setting, limit in [('MAX_TAR_BYTES', 1024), ('MAX_TAR_PADDING', 1024), ('MAX_TAR_MEMBERS', 1)]:
                with self.subTest(setting=setting), patch.object(q, setting, limit), self.assertRaises(ValueError):
                    next(q.members(path))
            header = tarfile.TarInfo('pax-header'); header.type = tarfile.XHDTYPE; header.size = 4 * 1024**2 + 1
            path.write_bytes(header.tobuf() + bytes(1024))
            with self.assertRaisesRegex(ValueError, 'extension metadata'):next(q.members(path))
            info = tarfile.TarInfo('sparse'); info.type = tarfile.GNUTYPE_SPARSE
            path.write_bytes(info.tobuf(format=tarfile.GNU_FORMAT) + bytes(1024))
            with self.assertRaisesRegex(ValueError, 'sparse'):next(q.members(path))

    def test_shared_tar_bounds_recursive_pax_headers_and_rejects_sparse_maps_before_parsing(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'source.tar'
            global_header = tarfile.TarInfo.create_pax_global_header({'comment': 'ordinary global metadata'})
            path.write_bytes(global_header * 3 + self.tar_bytes())
            self.assertEqual(q.tar_member_bytes(path, 'COPYING'), b'original notice')
            path.write_bytes(global_header * 33 + self.tar_bytes())
            with self.assertRaisesRegex(ValueError, 'extension headers'):next(q.members(path))
            stream = io.BytesIO()
            with tarfile.open(fileobj=stream, mode='w', format=tarfile.PAX_FORMAT) as archive:
                entry = tarfile.TarInfo('sparse'); entry.size = 2
                entry.pax_headers = {'GNU.sparse.major': '1', 'GNU.sparse.minor': '0', 'GNU.sparse.realsize': '1000'}
                archive.addfile(entry, io.BytesIO(b'0\n'))
            path.write_bytes(stream.getvalue())
            with self.assertRaisesRegex(ValueError, 'Sparse'):next(q.members(path))

    def test_zip_appended_to_tar_cannot_bypass_the_shared_tar_tail_boundary(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); inner = io.BytesIO()
            with zipfile.ZipFile(inner, 'w') as archive:archive.writestr('COPYING', b'contradictory ZIP notice')
            polyglot = self.tar_bytes() + inner.getvalue()
            self.assertTrue(zipfile.is_zipfile(io.BytesIO(polyglot)))
            self.assertFalse(q.archive_is_zip(polyglot))
            path = root / 'source.zip'; path.write_bytes(polyglot)
            for consume in [lambda:q.notice_bytes(root, 'source.zip::COPYING'),
                            lambda:q.inspection_member(path, 'COPYING', 1000),
                            lambda:q.inspection_member(path, None, 100000)]:
                with self.assertRaises(ValueError):consume()

    def test_tar_metadata_budget_precedes_the_actual_stdlib_payload_read(self):
        class HeaderOnly(io.BytesIO):
            reads = None
            def read(self, size=-1):
                self.reads.append(size)
                if size < 0 or size > 512:
                    raise AssertionError('Metadata payload read before budget admission')
                return super().read(size)
        for kind in [tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK]:
            with self.subTest(kind=kind):
                info = tarfile.TarInfo('oversized-metadata'); info.type = kind; info.size = 4 * 1024**2 + 1
                stream = HeaderOnly(info.tobuf(format=tarfile.GNU_FORMAT) + bytes(1024)); stream.reads = []
                with self.assertRaisesRegex(ValueError, 'extension metadata'):
                    tarfile.open(fileobj=stream, mode='r:', tarinfo=q.BoundedTarInfo)
                self.assertEqual(stream.reads, [512])

    def test_tar_recursive_pax_and_gnu_headers_count_once_at_the_exact_budget(self):
        for format in [tarfile.PAX_FORMAT, tarfile.GNU_FORMAT]:
            with self.subTest(format=format), tempfile.TemporaryDirectory() as tmp:
                stream = io.BytesIO(); long_name = 'long-path-' * 30
                with tarfile.open(fileobj=stream, mode='w', format=format) as archive:
                    for name in [long_name, 'second-file']:
                        info = tarfile.TarInfo(name); info.size = 7
                        archive.addfile(info, io.BytesIO(b'content'))
                path = Path(tmp) / 'source.tar'; path.write_bytes(stream.getvalue())
                # One extension, two regular headers and one end marker.
                with patch.object(q, 'MAX_TAR_MEMBERS', 4):
                    self.assertEqual([name for name, _, _ in q.members(path)], [long_name, 'second-file'])
                    self.assertEqual(q.tar_member_bytes(path, long_name), b'content')
                with patch.object(q, 'MAX_TAR_MEMBERS', 3), self.assertRaisesRegex(ValueError, 'extension headers'):
                    next(q.members(path))

    def test_tar_recursive_gnu_depth_has_a_valid_boundary_and_no_private_dispatch_bypass(self):
        with tempfile.TemporaryDirectory() as tmp:
            value = b'long-gnu-name-' * 20
            info = tarfile.TarInfo('././@LongLink'); info.type = tarfile.GNUTYPE_LONGNAME; info.size = len(value) + 1
            prefix = info.tobuf(format=tarfile.GNU_FORMAT) + value + b'\0' + bytes(-(len(value) + 1) % 512)
            path = Path(tmp) / 'source.tar'
            path.write_bytes(prefix * 31 + self.tar_bytes('placeholder'))
            self.assertEqual(q.tar_member_bytes(path, value.decode()), b'original notice')
            path.write_bytes(prefix * 32 + self.tar_bytes('placeholder'))
            with self.assertRaisesRegex(ValueError, 'extension headers'):next(q.members(path))


if __name__ == '__main__':
    unittest.main()
