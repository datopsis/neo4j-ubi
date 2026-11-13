#!/usr/bin/env python3
"""Keep one issue; notify only when the deferred set changes on trusted main."""
import argparse
import hashlib
import json
import os
import subprocess
from pathlib import Path

from scan_gate import cell

MARKER = '<!-- neo4j-ubi-repository-fix-tracker -->'
TITLE = 'UBI repository fix availability'


def api(repo, endpoint, method='GET', payload=None):
    command = ['gh', 'api', f'repos/{repo}/{endpoint}']
    if method == 'GET':
        command += ['--paginate', '--slurp']
    else:
        command += ['--method', method, '--input', '-']
    result = subprocess.run(command, input=json.dumps(payload) if payload is not None else None,
                            text=True, capture_output=True, check=True, timeout=60)
    return json.loads(result.stdout)


def state(directory):
    reports = [json.loads(path.read_text()) for path in directory.rglob('vulnerabilities.json')]
    if len(reports) != 2 or {r['architecture'] for r in reports} != {'amd64', 'arm64'}:
        raise ValueError('missing, duplicate or invalid admission evidence; preserve tracking issue')
    deferred = []
    fields = ['scanner', 'id', 'package', 'installed', 'severity', 'fixes', 'decision']
    for report in reports:
        rows = report.get('findings')
        if report.get('schema_version') != 1 or not isinstance(rows, list):
            raise ValueError('invalid admission evidence')
        for row in rows:
            if not isinstance(row, dict) or not set(fields) <= row.keys() or row['decision'] not in ['block', 'deferred', 'unfixed']:
                raise ValueError('invalid admission decision')
            if row['decision'] != 'deferred':
                continue
            if not isinstance(row['fixes'], list) or not row['fixes'] or any(not isinstance(v, str) or not v for v in row['fixes']):
                raise ValueError('invalid deferred fixed versions')
            item = {k: row[k] for k in fields if k != 'decision'}
            item['fixes'] = sorted(set(item['fixes']))
            item['architecture'] = report['architecture']
            deferred.append(item)
    # Ignore run URLs, timestamps, ordering, query candidates, unrelated blockers
    # and unfixed findings: only changes to the deferred set cause comments.
    return [json.loads(row) for row in sorted({json.dumps(r, sort_keys=True) for r in deferred})]


def render(deferred, run_url):
    digest = hashlib.sha256(json.dumps(deferred, sort_keys=True).encode()).hexdigest()
    fingerprint = f'<!-- deferred-sha256:{digest} -->'
    lines = [MARKER, fingerprint, '', 'Tracks vendor RPM fixes not yet available from the build\'s UBI repositories.',
             'Deferred findings remain vulnerabilities. An installable fix blocks the next gate.', '',
             f'[Native CI evidence]({run_url})', '',
             'Architecture | Scanner | Finding | Package | Installed | Severity | Vendor fixed version',
             '--- | --- | --- | --- | --- | --- | ---']
    for row in deferred:
        lines.append(' | '.join(cell(v) for v in [row['architecture'], row['scanner'], row['id'], row['package'],
                                                row['installed'], row['severity'], ', '.join(row['fixes'])]))
    if not deferred:
        lines += ['', 'No deferred findings. Check CI for installable fixes that now block, other blockers, and unfixed findings.',
                  'An empty deferred set does not imply a clean scan or passing CI.']
    return '\n'.join(lines) + '\n', fingerprint


def update(repo, deferred, run_url, call=api):
    body, fingerprint = render(deferred, run_url)
    pages = call(repo, 'issues?state=all&per_page=100')
    issues = [i for page in pages for i in page if not i.get('pull_request') and MARKER in (i.get('body') or '')]
    if len(issues) > 1:
        raise ValueError('multiple tracking issues; refusing to create another')
    if not issues:
        if deferred:
            return call(repo, 'issues', 'POST', {'title': TITLE, 'body': body})
        return None
    issue = issues[0]
    desired = 'open' if deferred else 'closed'
    if fingerprint in issue['body']:
        if issue['state'] == desired:
            return issue
        return call(repo, f'issues/{issue["number"]}', 'PATCH', {'state': desired})
    # A retry after a successful comment but failed issue update must not duplicate
    # the notification. Only the last comment matters when a prior set recurs.
    pages = call(repo, f'issues/{issue["number"]}/comments?per_page=100')
    comments = [comment for page in pages for comment in page]
    if not comments or fingerprint not in comments[-1]['body']:
        call(repo, f'issues/{issue["number"]}/comments', 'POST', {'body': 'Deferred set changed.\n\n' + body})
    return call(repo, f'issues/{issue["number"]}', 'PATCH', {'body': body, 'state': desired})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args()
    deferred = state(args.directory)
    repo = os.environ['GITHUB_REPOSITORY']
    run_url = f'https://github.com/{repo}/actions/runs/{os.environ["GITHUB_RUN_ID"]}'
    if args.dry_run:
        print(render(deferred, run_url)[0])
    else:
        if os.environ.get('GITHUB_EVENT_NAME') not in ['schedule', 'workflow_dispatch'] or os.environ.get('GITHUB_REF') != 'refs/heads/main':
            raise ValueError('issue updates require a scheduled or manual main-branch run')
        print(json.dumps(update(repo, deferred, run_url)))


if __name__ == '__main__':
    main()
