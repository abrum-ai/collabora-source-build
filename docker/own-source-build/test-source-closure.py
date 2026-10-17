#!/usr/bin/env python3
"""Exercise real OCI/archive boundaries and publication gates without a registry."""
import copy
import hashlib
import gzip
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import urllib.error

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


class SourceClosure(unittest.TestCase):
    def seed(self, root):
        license_file = root / 'LICENSE'; license_file.write_text('MPL license fixture\n')
        inputs = root / 'inputs.json'; inputs.write_text('{"commit":"' + COMMIT + '"}\n')
        proof = q.seed_layout(REPO, 'source-build-runtime-public', license_file, inputs, 'arm64', root / 'oci')
        return license_file, inputs, proof

    def fixture(self, root):
        (root / 'source-evidence').mkdir()
        (root / 'source-evidence/online-source.tar.zst').write_bytes(b'fixture source archive bytes')
        (root / 'LICENSE').write_text('License fixture\n')
        q.save(root / 'build-binding.json', {'runtime_digest': DIGEST, 'source_evidence_digest': SOURCE})
        q.save(root / 'runtime-inventory.json', {'layers': ['actual layer inventory fixture']})
        q.save(root / 'components.json', {'engine:one': {'kind': 'engine'}})
        review = {'schema': 'source-closure-review/1', 'closure_digest': CLOSURE,
                  'runtime_digest': DIGEST, 'source_evidence_digest': SOURCE,
                  'components_sha256': q.sha(root / 'components.json'),
                  'inventory_sha256': q.sha(root / 'runtime-inventory.json'),
                  'independent_review': {'reviewer': 'Independent reviewer', 'reference': 'reviewed immutable source reference',
                                         'scope': 'all-delivered-components-and-source-obligations'},
                  'components': {'engine:one': {'license_decision': 'MPL-2.0',
                      'source_files': {'source-evidence/online-source.tar.zst': q.sha(root / 'source-evidence/online-source.tar.zst')},
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


if __name__ == '__main__':
    unittest.main()
