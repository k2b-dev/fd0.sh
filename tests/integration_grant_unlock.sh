#!/usr/bin/env bash
# Secret grants on a locked vault ask for one authentication, shown after the
# request, that both unlocks and authorizes the grant; on an unlocked vault the
# grant still asks once after its review. Local server and test binaries only.
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/integration_isolation.sh"
fd0_test_require_isolation
trap fd0_test_stop_agents EXIT
python3 - <<'PY'
import os, pathlib, pty, select, socket, subprocess, time, urllib.request
root = pathlib.Path(os.environ['FD0_TEST_ROOT'])
cli = os.environ['FD0']
server_bin = str(pathlib.Path(os.environ['HOME']) / 'go/bin/fd0-server')
with socket.socket() as probe:
    probe.bind(('127.0.0.1', 0)); port = probe.getsockname()[1]
url = f'http://127.0.0.1:{port}'
fd0_home = root / 'device'
fd0_home.mkdir()
(fd0_home / 'config.toml').write_text(f'[sync]\nserver = "{url}"\non_unlock = false\n')
env = dict(os.environ, FD0_HOME=str(fd0_home), FD0_SSH_SOCK=str(root / 'ssh.sock'), FD0_AUTO_PIN='1')
passphrase = 'grant-passphrase'

def run(*args, stdin=None, success=True):
    result = subprocess.run([cli, *args], input=stdin, text=True, capture_output=True, env=env, timeout=60)
    if success and result.returncode:
        raise AssertionError(f'{args[:3]} failed: {result.stderr}')
    if not success and not result.returncode:
        raise AssertionError(f'{args[:3]} unexpectedly succeeded')
    return result

def in_terminal(*args):
    # Grants insist on a terminal; answer every passphrase prompt.
    pid, fd = pty.fork()
    if pid == 0:
        os.execve(cli, [cli, *args], env)
    output, answered = b'', 0
    deadline = time.time() + 60
    while time.time() < deadline:
        ready, _, _ = select.select([fd], [], [], 0.5)
        if ready:
            try:
                chunk = os.read(fd, 4096)
            except OSError:
                break
            if not chunk:
                break
            output += chunk
            if output.count(b'Passphrase:') > answered:
                os.write(fd, passphrase.encode() + b'\n'); answered += 1
    _, status = os.waitpid(pid, 0)
    return os.waitstatus_to_exitcode(status), output.decode(errors='replace')

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

    run('init', stdin=f'{passphrase}\n{passphrase}\n')
    run('unlock', stdin=f'{passphrase}\n')
    run('sync')
    run('scope', 'create', '--label', 'ops')
    run('secret', 'set', 'api-token', 'GRANT_CANARY_1', '--scope', 'ops')
    run('secret', 'set', 'other-token', 'GRANT_CANARY_2', '--scope', 'ops')

    # Locked: the request comes first, then exactly one authentication.
    run('lock')
    code, text = in_terminal('secret', 'grant', 'api-token', '--scope', 'ops', '--ttl', '24h')
    assert code == 0, text
    assert text.count('Passphrase:') == 1, text
    assert text.index('secret api-token in ops') < text.index('Passphrase:'), text
    assert 'secret grant saved' in text and 'GRANT_CANARY' not in text, text
    assert 'unlocked' in run('status').stdout + run('status').stderr

    # Unlocked: the full review, then one authentication, as before.
    code, text = in_terminal('secret', 'grant', 'other-token', '--scope', 'ops', '--ttl', '24h')
    assert code == 0, text
    assert text.count('Passphrase:') == 1 and 'Authenticate again' in text, text

    # A locked request that cannot be resolved fails after the one prompt.
    run('lock')
    code, text = in_terminal('secret', 'grant', 'missing', '--scope', 'ops')
    assert code != 0 and text.count('Passphrase:') == 1, text

    # Both grants serve their values while locked.
    run('lock')
    assert run('secret', 'get', 'api-token', '--scope', 'ops', '--raw').stdout == 'GRANT_CANARY_1'
    assert run('secret', 'get', 'other-token', '--scope', 'ops', '--raw').stdout == 'GRANT_CANARY_2'
    print('integration_grant_unlock: ok')
finally:
    server.terminate(); server.wait(10)
PY
