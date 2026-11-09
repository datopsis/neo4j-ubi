#!/usr/bin/env python3
"""Real database, restart, guard and process checks on a native Docker/Podman host."""
import base64
import json
import os
import secrets
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

RUNTIME = os.environ.get('CONTAINER_RUNTIME', 'docker')
IMAGE = os.environ.get('IMAGE', 'localhost/neo4j-ubi:dev')
PREFIX = 'neo4j-test-' + secrets.token_hex(5)
containers = []
volumes = []
password = '-' + secrets.token_urlsafe(32) + '"#\\ space'


def run(*args, check=True):
    result = subprocess.run([RUNTIME, *args], check=False, text=True, capture_output=True, timeout=90)
    if check and result.returncode:
        output = result.stdout + result.stderr
        assert password not in output, 'credential leaked in failed command output'
        raise RuntimeError(f'{RUNTIME} {args[0]} failed ({result.returncode}): {output}')
    return result


def volume():
    name = PREFIX + '-' + str(len(volumes))
    run('volume', 'create', name)
    volumes.append(name)
    return name


def start(label, data, secret=None, extra=()):
    name = PREFIX + '-' + label
    containers.append(name)
    args = ['run', '-d', '--name', name, '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges',
            '--memory=2g', '--cpus=2', '--pids-limit=256',
            '--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=256m,mode=1777',
            '--tmpfs=/run/neo4j:rw,noexec,nosuid,nodev,size=64m,uid=10001,gid=0,mode=0700',
            '-p', '127.0.0.1::7474', '-p', '127.0.0.1::7687']
    if data:
        args += ['--mount', f'type=volume,source={data},target=/data']
    if secret:
        args += ['--mount', f'type=bind,source={secret},target=/run/secrets/neo4j-password,readonly']
    args += list(extra) + [IMAGE]
    run(*args)
    return name


def logs(name):
    result = run('logs', name, check=False)
    assert password not in result.stdout + result.stderr, 'credential leaked to logs'
    return result.stdout + result.stderr


def rejected(name, message):
    result = run('wait', name)
    assert result.stdout.strip() not in ('0', ''), f'{name} unexpectedly succeeded'
    output = logs(name)
    assert message in output, f'expected {message!r}: {output}'
    print(f'PASS guard: {message}')


def url(name):
    port = run('port', name, '7474/tcp').stdout.strip().split(':')[-1]
    return 'http://127.0.0.1:' + port


def request(name, statement=None, auth=True):
    headers = {'Accept': 'application/json'}
    if auth:
        headers['Authorization'] = 'Basic ' + base64.b64encode(('neo4j:' + password).encode()).decode()
    data = None
    path = '/'
    if statement:
        path = '/db/neo4j/tx/commit'
        data = json.dumps({'statements': [{'statement': statement}]}).encode()
        headers['Content-Type'] = 'application/json'
    with urllib.request.urlopen(urllib.request.Request(url(name) + path, data=data, headers=headers), timeout=10) as response:
        return json.load(response)


def ready(name):
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        try:
            result = request(name, 'RETURN 1')
            if not result['errors']:
                return
        except (urllib.error.URLError, OSError):
            pass
        if run('inspect', '--format', '{{.State.Running}}', name).stdout.strip() != 'true':
            raise AssertionError(logs(name))
        time.sleep(2)
    raise AssertionError('readiness timeout: ' + logs(name))


def query(name, statement):
    result = request(name, statement)
    assert not result['errors'], result
    return result['results'][0]['data']


def stop(name):
    run('stop', '--time=45', name)
    state = json.loads(run('inspect', name).stdout)[0]['State']
    assert state['ExitCode'] == 0 and not state.get('OOMKilled', False), state
    logs(name)
    run('rm', name)
    containers.remove(name)


def main():
    lock = json.loads(Path('artifacts/neo4j.lock.json').read_text())
    with tempfile.TemporaryDirectory() as temp:
        secret = Path(temp) / 'password'
        secret.write_text(password + '\n')
        secret.chmod(0o440)
        if RUNTIME == 'docker':
            subprocess.run(['sudo', 'chown', '10001:0', str(secret)], check=True)
        data = volume()
        rejected(start('missing-credential', data), 'operator credential required')
        rejected(start('missing-volume', None, secret), '/data requires an explicit')
        rejected(start('root', data, secret, ['--user=0']), 'must start as a non-root')
        rejected(start('bad-opt-out', data, secret, ['-e', 'NEO4J_UBI_ALLOW_NO_AUTH=yes']), 'must be true or false')
        rejected(start('bad-memory', data, secret, ['-e', 'NEO4J_UBI_HEAP=bad']), 'NEO4J_UBI_HEAP')
        rejected(start('unsupported', data, secret, ['-e', 'NEO4J_AUTH=none']), 'unsupported configuration variable')
        bad = Path(temp) / 'invalid'
        bad.write_text(secrets.token_hex(2))
        bad.chmod(0o440)
        if RUNTIME == 'docker':
            subprocess.run(['sudo', 'chown', '10001:0', str(bad)], check=True)
        rejected(start('short-credential', data, bad), 'at least 16 printable')
        for label, content, mode, diagnostic in [
            ('empty', '', 0o440, 'at least 16 printable'),
            ('multiline', password + '\nextra', 0o440, 'one line'),
            ('nul', password + '\x00', 0o440, 'NUL bytes'),
            ('world-readable', password, 0o444, 'must not be accessible to others'),
        ]:
            path = Path(temp) / label
            path.write_text(content)
            path.chmod(mode)
            if RUNTIME == 'docker':
                subprocess.run(['sudo', 'chown', '10001:0', str(path)], check=True)
            rejected(start(label, data, path), diagnostic)
        name = start('server', data, secret)
        ready(name)
        components = query(name, 'CALL dbms.components() YIELD versions, edition RETURN versions[0], edition')[0]['row']
        assert components == [lock['neo4j']['version'], 'community'], components
        assert request(name)['neo4j_version'] == lock['neo4j']['version']
        try:
            request(name, 'RETURN 1', auth=False)
            raise AssertionError('unauthenticated transaction was accepted')
        except urllib.error.HTTPError as error:
            assert error.code == 401
        query(name, "CREATE (:Smoke {id: 42})")
        run('exec', name, '/usr/local/bin/neo4j-healthcheck')
        # Every live process, including the launcher and JVM, must be unprivileged.
        process_check = r'''
set -eux
readonly_root=false
while read -r _ _ _ _ target options _; do
  if [[ $target == / && ,$options, == *,ro,* ]]; then readonly_root=true; fi
done < /proc/self/mountinfo
$readonly_root
for status in /proc/[0-9]*/status; do
  while read -r key a b c d; do
    case "$key" in
      Uid:) test "$a" != 0; test "$b" != 0; test "$c" != 0; test "$d" != 0 ;;
      CapEff:|CapPrm:|CapBnd:|CapInh:|CapAmb:) test "$a" = 0000000000000000 ;;
      NoNewPrivs:) test "$a" = 1 ;;
    esac
  done < "$status"
done
for tool in rpm dnf microdnf yum curl wget gcc javac; do ! command -v "$tool"; done
test ! -d /etc/yum.repos.d
test ! -d /etc/pki/rpm-gpg
test ! -e /run/neo4j/initial-password.args
test -r /opt/neo4j/native/libjnidispatch.so
test ! -w /opt/neo4j/native/libjnidispatch.so
test ! -d /run/neo4j/.cache/JNA
! touch /etc/read-only-test
'''
        run('exec', name, 'bash', '-c', process_check)
        # Secret must not survive in any process argv/environment.
        process = run('exec', name, 'bash', '-c', 'cat /proc/[0-9]*/cmdline /proc/[0-9]*/environ 2>/dev/null || true').stdout
        assert password not in process
        java = run('exec', name, '/opt/java/bin/java', '-version')
        assert lock['architectures'][os.environ['ARCHITECTURE']]['jre']['version'][4:].split('+')[0] in java.stderr
        print('PASS authenticated Cypher, Community/version, HTTP, UID/caps/NNP, read-only root, secret hygiene')
        stop(name)
        name = start('restart', data, secret)
        ready(name)
        assert query(name, 'MATCH (n:Smoke) RETURN n.id')[0]['row'] == [42]
        stop(name)
        print('PASS graceful shutdown and persistence across container replacement')
        unauthenticated_data = volume()
        name = start('explicit-no-auth', unauthenticated_data, extra=['-e', 'NEO4J_UBI_ALLOW_NO_AUTH=true'])
        ready(name)
        assert not request(name, 'RETURN 1', auth=False)['errors']
        assert 'authentication explicitly disabled' in logs(name)
        stop(name)
        rejected(start('unsafe-auth-transition', unauthenticated_data, secret), 'lacks authenticated initialization marker')
        print('PASS explicit unauthenticated opt-out and fail-closed auth re-enablement')


if __name__ == '__main__':
    try:
        main()
    except Exception:
        for container in containers:
            print(logs(container))
        raise
    finally:
        for container in containers:
            run('rm', '-f', container, check=False)
        for name in volumes:
            run('volume', 'rm', name, check=False)
