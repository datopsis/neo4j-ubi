import copy
import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / f'{name}.py')
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


class PolicyTests(unittest.TestCase):
    def test_lock_rejects_unsafe_inputs(self):
        artifacts = module('artifacts')
        lock = json.loads((ROOT / 'artifacts/neo4j.lock.json').read_text())
        artifacts.validate(lock)
        for change in ('edition', 'digest', 'architecture', 'base'):
            broken = copy.deepcopy(lock)
            if change == 'edition':
                broken['neo4j']['url'] = broken['neo4j']['url'].replace('community', 'enterprise')
            elif change == 'digest':
                broken['neo4j']['sha256'] = 'bad'
            elif change == 'architecture':
                del broken['architectures']['arm64']
            else:
                broken['bases']['runtime']['reference'] = 'registry.access.redhat.com/ubi9/ubi-micro:latest'
            with self.subTest(change=change), self.assertRaises(ValueError):
                artifacts.validate(broken)

    def test_corrupt_cached_artifact_is_rejected(self):
        artifacts = module('artifacts')
        with tempfile.TemporaryDirectory() as temp:
            artifacts.ROOT = Path(temp)
            expected = artifacts.digest(b'trusted bytes')
            path = Path(temp) / '.cache/artifacts' / expected
            path.parent.mkdir(parents=True)
            path.write_bytes(b'trusted bytes')
            item = {'sha256': expected, 'url': 'https://example.invalid/never-requested'}
            self.assertEqual(artifacts.download(item), path)
            path.write_bytes(b'altered bytes')
            with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
                artifacts.download(item)

    def test_archive_traversal_rejected(self):
        import io
        import tarfile
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'bad.tar'
            with tarfile.open(path, 'w') as tar:
                item = tarfile.TarInfo('../escape')
                item.size = 1
                tar.addfile(item, io.BytesIO(b'x'))
            with self.assertRaises(ValueError):
                module('artifacts').extract(path, Path(temp) / 'output')

    def test_parquet_exclusion_requires_review_for_changed_inputs(self):
        # Execute the actual Containerfile exclusion, stopping before image copy.
        containerfile = (ROOT / 'Containerfile').read_text()
        exclusion = containerfile.split('RUN { test ', 1)[1].split('    && cp -a /bundle/neo4j', 1)[0]
        exclusion = ('{ test ' + exclusion).replace('\\\n', '')
        for case in ('current', 'neo4j-upgrade', 'parquet-upgrade', 'missing', 'extra'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temp:
                bundle = Path(temp) / 'bundle'
                lib = bundle / 'neo4j/lib'
                lib.mkdir(parents=True)
                other = lib / 'parquet-hadoop-1.18.1.jar'
                other.write_bytes(b'retain unchanged')
                excluded = lib / 'parquet-jackson-1.18.1.jar'
                if case != 'missing':
                    excluded.write_bytes(b'excluded')
                if case == 'parquet-upgrade':
                    excluded.rename(lib / 'parquet-jackson-1.18.2.jar')
                if case == 'extra':
                    plugins = bundle / 'neo4j/plugins'
                    plugins.mkdir()
                    (plugins / 'parquet-jackson-1.18.2.jar').write_bytes(b'new copy')
                version = '2026.11.0' if case == 'neo4j-upgrade' else '2026.10.2'
                result = subprocess.run(['bash', '-o', 'pipefail', '-c', exclusion.replace('/bundle', str(bundle))],
                                        env={**os.environ, 'NEO4J_VERSION': version}, capture_output=True, text=True)
                self.assertEqual(other.read_bytes(), b'retain unchanged')
                if case == 'current':
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertFalse(excluded.exists())
                else:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn('Revisit the parquet-jackson exclusion', result.stderr)
                    if case in ('neo4j-upgrade', 'extra'):
                        self.assertTrue(excluded.exists(), 'reject before removing anything')

    def test_server_logs_reject_class_loading_errors(self):
        spec = importlib.util.spec_from_file_location('runtime', ROOT / 'tests/runtime.py')
        runtime = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runtime)
        with patch.object(runtime, 'logs', return_value='INFO Started.\n'):
            runtime.clean_server_logs('test')
        for output in ('INFO Starting...\n',
                       'INFO Started.\njava.lang.NoClassDefFoundError: shaded/parquet/Mapper',
                       'INFO Started.\njava.lang.ClassNotFoundException: example.Class',
                       'INFO Started.\njava.lang.NoSuchMethodError: example.method',
                       'INFO Started.\nFailed to load procedure class example.Procedure'):
            with self.subTest(output=output), patch.object(runtime, 'logs', return_value=output):
                with self.assertRaises(AssertionError):
                    runtime.clean_server_logs('test')

    def test_scan_gate_blocks_each_scanner(self):
        scanner = module('scan_gate')
        trivy = {'SchemaVersion': 2, 'Results': []}
        grype = {'descriptor': {'name': 'grype'}, 'matches': []}
        self.assertFalse(scanner.gate(trivy, grype))
        trivy['Results'] = [{'Vulnerabilities': [{'Severity': 'HIGH', 'VulnerabilityID': 'test',
                                               'PkgName': 'p', 'InstalledVersion': '1', 'FixedVersion': '2'}]}]
        self.assertTrue(scanner.gate(trivy, grype))
        trivy['Results'][0]['Vulnerabilities'][0]['FixedVersion'] = ''
        self.assertFalse(scanner.gate(trivy, grype))
        grype['matches'] = [{'artifact': {'name': 'p', 'version': '1'}, 'vulnerability': {
            'id': 'test', 'severity': 'Critical', 'fix': {'state': 'fixed', 'versions': ['2']}}}]
        self.assertTrue(scanner.gate(trivy, grype))
        grype['matches'][0]['vulnerability']['fix'] = {'state': 'not-fixed', 'versions': []}
        self.assertFalse(scanner.gate(trivy, grype))
        with self.assertRaises(ValueError):
            scanner.gate({}, grype)
        with self.assertRaises(ValueError):
            scanner.gate(trivy, {})
