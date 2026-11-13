"""Admission, reporting and notification regression tests."""
import copy
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from test_policy import module

gate = module('scan_gate')

tracker = module('track_vulnerabilities')


def finding():
    return dict(scanner='Trivy', id='CVE-test', package='sample', severity='HIGH', installed='1.0-1',
                fixes=['1.0-2'], fix_reported=True, rpm=True, package_arch='x86_64')


def response(available):
    return {'repositories': {'urls': {}}, 'results': [{'available': available, 'candidates': ['0:1.0-1']}]}


class AvailabilityTests(unittest.TestCase):
    def test_available_blocks_unavailable_defers_each_architecture_and_severity(self):
        for arch, rpm_arch in [('amd64', 'x86_64'), ('arm64', 'aarch64')]:
            for severity in ['HIGH', 'CRITICAL']:
                for available in [True, False]:
                    row = finding() | {'package_arch': rpm_arch, 'severity': severity}
                    query = Mock(return_value=response(available))
                    rows, evidence = gate.evaluate([row], arch, query)
                    self.assertEqual(rows[0]['decision'], 'block' if available else 'deferred')
                    query.assert_called_once_with([{'name': 'sample', 'fixes': ['1.0-2']}], arch)
                    self.assertIn('1.0-2', gate.summary(rows, arch))
                    self.assertEqual(evidence, response(available))

    def test_query_failures_block(self):
        for error in [TimeoutError('timeout'), subprocess.TimeoutExpired('dnf', 180),
                      subprocess.CalledProcessError(1, 'dnf'), ValueError('missing repository')]:
            rows, _ = gate.evaluate([finding()], 'amd64', Mock(side_effect=error))
            self.assertEqual(rows[0]['decision'], 'block')
        for result in [{'error': 'unparsable EVR'}, {}, {'available': 'false', 'candidates': []},
                       {'available': False}]:
            rows, _ = gate.evaluate([finding()], 'amd64', lambda *_: {'results': [result]})
            self.assertEqual(rows[0]['decision'], 'block')
        rows, _ = gate.evaluate([finding(), finding()], 'amd64', lambda *_: response(False))
        self.assertTrue(all(r['decision'] == 'block' for r in rows))

    def test_non_rpm_unknown_identity_wrong_arch_and_missing_arch_block(self):
        for changes, arch in [({'rpm': False}, 'amd64'), ({'package_arch': None}, 'amd64'),
                              ({'package_arch': 'aarch64'}, 'amd64'), ({}, None)]:
            query = Mock(side_effect=AssertionError('must not query'))
            rows, _ = gate.evaluate([finding() | changes], arch, query)
            self.assertEqual(rows[0]['decision'], 'block')
            query.assert_not_called()

    def test_non_rpm_scanner_findings_block(self):
        for kind in ['jar', 'go-module', 'python', 'rust-crate', 'npm']:
            grype = {'descriptor': {'name': 'grype'}, 'matches': [{'artifact': {'name': 'sample', 'type': kind},
                                 'vulnerability': {'id': 'CVE-test', 'severity': 'Critical',
                                                   'fix': {'state': 'fixed', 'versions': ['2.0']}}}]}
            rows, _ = gate.evaluate(gate.findings({'SchemaVersion': 2, 'Results': []}, grype), 'amd64', Mock())
            self.assertEqual(rows[0]['decision'], 'block')

    def test_unfixed_stays_reported_without_query(self):
        query = Mock()
        rows, _ = gate.evaluate([finding() | {'fix_reported': False, 'fixes': []}], 'amd64', query)
        self.assertEqual(rows[0]['decision'], 'unfixed')
        self.assertIn('no fix reported', gate.summary(rows, 'amd64'))
        query.assert_not_called()

    def test_scanner_rpm_identity(self):
        purl = 'pkg:rpm/redhat/sample@1.0-1?arch=aarch64&distro=redhat-9'
        trivy = {'SchemaVersion': 2, 'Results': [{'Type': 'redhat', 'Class': 'os-pkgs', 'Vulnerabilities': [
            {'Severity': 'HIGH', 'VulnerabilityID': 'CVE-test', 'PkgName': 'sample', 'FixedVersion': '1.0-2',
             'PkgIdentifier': {'PURL': purl}}]}]}
        grype = {'descriptor': {'name': 'grype'}, 'matches': [{'artifact': {'name': 'sample', 'type': 'rpm', 'purl': purl},
                             'vulnerability': {'id': 'CVE-test', 'severity': 'High',
                                               'namespace': 'redhat:distro:redhat:9',
                                               'fix': {'state': 'fixed', 'versions': ['0:1.0-2']}}}]}
        for row in gate.findings(trivy, grype):
            self.assertTrue(row['rpm'])
            self.assertEqual(row['package_arch'], 'aarch64')
        for invalid in [None, '', purl.replace('sample@', 'other@'), purl.replace('rpm/', 'pypi/'),
                        purl + '&arch=x86_64']:
            self.assertIsNone(gate.rpm_arch(invalid, 'sample'))

    def test_fixed_state_without_version_blocks(self):
        row = finding() | {'fixes': []}
        rows, _ = gate.evaluate([row], 'amd64', lambda *_: {'results': [{'error': 'missing RPM fixed versions'}]})
        self.assertEqual(rows[0]['decision'], 'block')
        self.assertIn('unspecified', gate.summary(rows, 'amd64'))

    def test_system_rpm_and_dnf_unit_tests(self):
        result = subprocess.run(['/usr/bin/python3', 'tests/rpm_gate.py'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


    def test_grype_versions_block_even_without_fixed_state(self):
        grype = {'descriptor': {'name': 'grype'}, 'matches': [
            {'artifact': {'name': 'sample', 'type': 'java-archive', 'version': '1'},
             'vulnerability': {'id': 'test', 'severity': 'High', 'fix': {'versions': ['2']}}}]}
        self.assertTrue(gate.gate({'SchemaVersion': 2, 'Results': []}, grype))

    def test_noarch_rpm_can_defer(self):
        rows, _ = gate.evaluate([finding() | {'package_arch': 'noarch'}], 'arm64', lambda *_: response(False))
        self.assertEqual(rows[0]['decision'], 'deferred')

    def test_partial_error_response_cannot_leave_deferred_decisions(self):
        rows, _ = gate.evaluate([finding(), finding()], 'amd64',
                                lambda *_: {'results': [{'available': False, 'candidates': []}, None]})
        self.assertEqual([r['decision'] for r in rows], ['block', 'block'])

    def test_repoquery_rejects_missing_repository_evidence(self):
        result = Mock(stdout='{"results": [{"available": false, "candidates": []}]}')
        with patch.object(gate.subprocess, 'run', return_value=result):
            rows, _ = gate.evaluate([finding()], 'amd64')
        self.assertEqual(rows[0]['decision'], 'block')


class TrackingTests(unittest.TestCase):
    def report(self, arch='amd64', decision='deferred'):
        return {'schema_version': 1, 'architecture': arch,
                'findings': [finding() | {'decision': decision}]}

    def write_reports(self, directory, decision='deferred'):
        import json
        for arch in ['amd64', 'arm64']:
            path = Path(directory, arch, 'vulnerabilities.json')
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(self.report(arch, decision)))

    def deferred(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.write_reports(tmp)
            return tracker.state(Path(tmp))

    def test_create_one_issue_and_no_comment_on_unchanged_set(self):
        value = self.deferred()
        call = Mock(side_effect=[[], {'number': 7}])
        tracker.update('owner/repo', value, 'https://example.invalid/run/1', call)
        self.assertEqual(call.call_args.args[1:3], ('issues', 'POST'))
        body = tracker.render(value, '')[0]
        call = Mock(return_value=[[{'number': 7, 'body': body, 'state': 'open'}]])
        tracker.update('owner/repo', value, 'https://example.invalid/run/2', call)
        self.assertEqual(call.call_count, 1)

    def test_changed_fix_comments_once(self):
        value = self.deferred()
        body = tracker.render(value, '')[0]
        changed = copy.deepcopy(value)
        changed[0]['fixes'] = ['1.0-3']
        call = Mock(side_effect=[[[{'number': 7, 'body': body, 'state': 'open'}]], [], {}, {}])
        tracker.update('owner/repo', changed, '', call)
        self.assertEqual(call.call_args_list[2].args[1:3], ('issues/7/comments', 'POST'))
        self.assertIn('1.0-3', call.call_args_list[2].args[3]['body'])

    def test_publication_closes_issue_and_new_deferral_reopens_same_issue(self):
        for before, after, current, desired in [(self.deferred(), [], 'open', 'closed'),
                                                ([], self.deferred(), 'closed', 'open')]:
            body = tracker.render(before, '')[0]
            call = Mock(side_effect=[[[{'number': 7, 'body': body, 'state': current}]], [], {}, {}])
            tracker.update('owner/repo', after, '', call)
            self.assertEqual(call.call_args.args[1:3], ('issues/7', 'PATCH'))
            self.assertEqual(call.call_args.args[3]['state'], desired)

    def test_missing_corrupt_and_duplicate_evidence_preserves_issue(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                tracker.state(Path(tmp))
            self.write_reports(tmp)
            Path(tmp, 'arm64/vulnerabilities.json').write_text('{}')
            with self.assertRaises((ValueError, KeyError)):
                tracker.state(Path(tmp))
            self.write_reports(tmp)
            Path(tmp, 'vulnerabilities.json').write_text(Path(tmp, 'amd64/vulnerabilities.json').read_text())
            with self.assertRaises(ValueError):
                tracker.state(Path(tmp))

    def test_unrelated_findings_and_ordering_do_not_change_deferred_set(self):
        import json
        with tempfile.TemporaryDirectory() as tmp:
            self.write_reports(tmp)
            before = tracker.state(Path(tmp))
            p = Path(tmp, 'amd64/vulnerabilities.json')
            report = json.loads(p.read_text())
            report['findings'] += [finding() | {'decision': 'block'}, finding() | {'decision': 'unfixed'}]
            report['findings'] *= 2
            report['findings'].reverse()
            report['query'] = {'candidates': ['new repository version']}
            p.write_text(json.dumps(report))
            self.assertEqual(before, tracker.state(Path(tmp)))
            self.assertEqual(tracker.render(before, 'run/1')[1], tracker.render(before, 'run/2')[1])

    def test_duplicate_issues_fail_and_empty_set_does_not_create_issue(self):
        call = Mock(return_value=[])
        tracker.update('owner/repo', [], '', call)
        self.assertEqual(call.call_count, 1)
        body = tracker.render(self.deferred(), '')[0]
        call = Mock(return_value=[[{'number': n, 'body': body} for n in [7, 8]]])
        with self.assertRaises(ValueError):
            tracker.update('owner/repo', self.deferred(), '', call)
        self.assertEqual(call.call_count, 1)

    def test_retry_after_comment_does_not_duplicate_notification(self):
        old_body = tracker.render(self.deferred(), '')[0]
        new_body = tracker.render([], '')[0]
        call = Mock(side_effect=[[[{'number': 7, 'body': old_body, 'state': 'open'}]],
                                 [[{'body': new_body}]], {}])
        tracker.update('owner/repo', [], '', call)
        self.assertEqual(call.call_count, 3)
        self.assertEqual(call.call_args.args[1:3], ('issues/7', 'PATCH'))

    def test_issue_write_rejected_on_pull_requests_and_non_main_dispatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.write_reports(tmp)
            for event, ref in [('pull_request', 'refs/pull/3/merge'), ('workflow_dispatch', 'refs/heads/feature')]:
                with patch('sys.argv', ['track_vulnerabilities.py', tmp]), patch.dict('os.environ', {
                    'GITHUB_EVENT_NAME': event, 'GITHUB_REF': ref, 'GITHUB_REPOSITORY': 'owner/repo', 'GITHUB_RUN_ID': '1'
                }), patch.object(tracker, 'update') as update:
                    with self.assertRaisesRegex(ValueError, 'main-branch'):
                        tracker.main()
                    update.assert_not_called()
