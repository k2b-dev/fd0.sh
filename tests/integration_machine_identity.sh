#!/usr/bin/env bash
# Machine identity end to end (docs/MACHINE_IDENTITIES_PLAN.md, phase A):
# a key-file identity pins the server by safety number, is admitted to a
# scope by a person, reads a service without prompts, and loses access after
# removal. Local server and test binaries only.
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/integration_isolation.sh"
fd0_test_require_isolation
trap fd0_test_stop_agents EXIT
python3 - <<'PY'
import json, os, pathlib, re, socket, subprocess, time, urllib.request
root = pathlib.Path(os.environ['FD0_TEST_ROOT'])
cli = os.environ['FD0']
server_bin = str(pathlib.Path(os.environ['HOME']) / 'go/bin/fd0-server')
with socket.socket() as probe:
    probe.bind(('127.0.0.1', 0)); port = probe.getsockname()[1]
url = f'http://127.0.0.1:{port}'

def home(name, auto_pin):
    path = root / name
    path.mkdir()
    (path / 'config.toml').write_text(f'[sync]\nserver = "{url}"\non_unlock = false\n')
    env = dict(os.environ, FD0_HOME=str(path), FD0_SSH_SOCK=str(root / f'{name}.sock'))
    env.pop('FD0_AUTO_PIN', None)
    if auto_pin:
        env['FD0_AUTO_PIN'] = '1'
    return env

person = home('person', True)
# The machine runs with on-unlock background sync and FD0_AUTO_PIN to prove
# that background sync never pins a server on first contact.
machine = home('machine', True)
(root / 'machine' / 'config.toml').write_text(f'[sync]\nserver = "{url}"\non_unlock = true\n')

def run(env, *args, stdin=None, success=True):
    result = subprocess.run([cli, *args], input=stdin, text=True, capture_output=True, env=env, timeout=60)
    if success and result.returncode:
        raise AssertionError(f'{args[:3]} failed: {result.stderr}')
    if not success and not result.returncode:
        raise AssertionError(f'{args[:3]} unexpectedly succeeded')
    return result

log = open(root / 'server.log', 'w')
server = subprocess.Popen([server_bin, '--bind', f'127.0.0.1:{port}', '--db', str(root / 'server.db'), '--no-ratelimit'], stdout=log, stderr=log)
try:
    for attempt in range(100):
        try:
            urllib.request.urlopen(url + '/health', timeout=.2).close(); break
        except Exception:
            time.sleep(.05)
    else:
        raise AssertionError('isolated server did not start')

    # A person keeps the deploy credentials in a dedicated scope.
    run(person, 'init', stdin='synthetic-password\nsynthetic-password\n')
    run(person, 'unlock', stdin='synthetic-password\n')
    run(person, 'scope', 'create', '--label', 'ci-deploy')
    run(person, 'service', 'add', 'app', '--scope', 'ci-deploy')
    run(person, 'service', 'set', 'app', 'token', '-', '--env', 'APP_TOKEN', '--scope', 'ci-deploy', stdin='MACHINE_IDENTITY_CANARY')
    run(person, 'sync')

    # The machine's key is provisioned outside fd0.
    key = root / 'machine.key'
    key.write_text('c3ludGhldGljLW1hY2hpbmUta2V5LWZvci10ZXN0cy0wMDE=\n')
    key.chmod(0o600)
    run(machine, 'init', '--key-file', str(key))
    run(machine, 'unlock', '--key-file', str(key))
    run(machine, 'unlock', '--key-file', str(key))  # idempotent

    agent_log = root / 'machine' / 'agent.log'
    for attempt in range(200):
        if agent_log.exists() and 'background sync never pins' in agent_log.read_text(errors='replace'):
            break
        time.sleep(.05)
    else:
        raise AssertionError('background sync did not run or did not refuse first contact')
    strict = dict(machine)
    strict.pop('FD0_AUTO_PIN')
    # Without a pin the first sync refuses but shows the safety number, which
    # also proves the background sync did not pin the server.
    refused = run(strict, 'sync', success=False)
    assert 'first-contact pinning required' in refused.stderr, refused.stderr
    groups = re.findall(r'\b\d{5}\b', refused.stderr.split('Server fingerprint', 1)[-1])
    assert len(groups) >= 12, refused.stderr
    # The person's own device shows the number it pinned; that is the trusted
    # source the machine is checked against.
    status = json.loads(run(person, 'status', '--json').stdout)
    pinned = [srv for srv in status.get('servers', []) if srv['url'] == url]
    assert len(pinned) == 1, status
    safety = ' '.join(pinned[0]['safetyNumber'].split())
    assert safety == ' '.join(groups[:12]), (safety, groups[:12])
    wrong = ' '.join(['00000'] * 12)
    assert 'does not match --pin' in run(machine, 'sync', '--pin', wrong, success=False).stderr
    run(machine, 'sync', '--pin', safety)
    run(machine, 'sync', '--pin', safety)   # existing pin is verified again
    run(machine, 'sync', '--pin', wrong, success=False)

    # A person admits the machine; the machine reads without prompts.
    card = run(machine, 'card', 'export').stdout.strip()
    run(person, 'card', 'import', card, '--label', 'ci-runner', '--yes')
    run(person, 'scope', 'add-member', 'ci-runner', '--scope', 'ci-deploy', '--role', 'reader')
    run(person, 'sync')
    run(machine, 'sync')
    env_out = run(machine, 'service', 'env', 'app', '--format', 'docker-env', '--scope', 'ci-deploy').stdout
    assert env_out == 'APP_TOKEN=MACHINE_IDENTITY_CANARY\n', env_out
    # fd0 run hands the value to a command's environment and keeps its exit status.
    ran = run(machine, 'run', '--service', 'app', '--scope', 'ci-deploy', '--', 'sh', '-c', 'printf %s "$APP_TOKEN"; exit 7', success=False)
    assert ran.returncode == 7 and ran.stdout == 'MACHINE_IDENTITY_CANARY', (ran.returncode, ran.stderr)
    members = run(person, 'scope', 'members', 'ci-deploy').stdout
    assert 'reader' in members and 'admin' in members, members

    # A reader cannot change values or membership; nothing is signed locally.
    denied = run(machine, 'service', 'set', 'app', 'token', '-', '--scope', 'ci-deploy', stdin='MACHINE_WRITE', success=False)
    assert 'role in' in denied.stderr and 'reader' in denied.stderr, denied.stderr
    denied = run(machine, 'scope', 'add-member', card, '--scope', 'ci-deploy', success=False)
    run(machine, 'sync')

    # Promoted to writer, the machine can rotate the value it consumes.
    run(person, 'scope', 'role', 'ci-runner', 'writer', '--scope', 'ci-deploy')
    run(person, 'sync')
    run(machine, 'sync')
    run(machine, 'service', 'set', 'app', 'token', '-', '--scope', 'ci-deploy', stdin='MACHINE_ROTATED')
    run(machine, 'sync')
    run(person, 'sync')
    assert run(person, 'service', 'get', 'app', 'token', '--raw', '--scope', 'ci-deploy').stdout == 'MACHINE_ROTATED'
    # The only admin cannot hand the scope over by leaving.
    assert 'only admin' in run(person, 'scope', 'leave', 'ci-deploy', '--yes', success=False).stderr

    # Removal ends access on the next sync.
    run(person, 'scope', 'remove-member', 'ci-runner', '--scope', 'ci-deploy', '--yes')
    run(person, 'sync')
    run(machine, 'sync')
    gone = run(machine, 'service', 'get', 'app', 'token', '--scope', 'ci-deploy', success=False)
    assert 'MACHINE_IDENTITY_CANARY' not in gone.stdout and 'ci-deploy' in gone.stderr, gone.stderr
    print('machine identity integration: key-file unlock, pinned sync, admission, read and removal verified')
finally:
    server.terminate(); server.wait(timeout=5)
PY
