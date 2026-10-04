#!/usr/bin/env bash
# Deploy recipes end to end (docs/SERVICES_PLAN.md, phase 3): an admin saves
# a recipe with targets, each device approves it in a terminal, deploys run
# locally with values on stdin, results sync to other members, readers can
# deploy without publishing results, and any recipe change needs a new
# approval. Local server and test binaries only; recipes write to a temp dir.
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/integration_isolation.sh"
fd0_test_require_isolation
trap fd0_test_stop_agents EXIT
python3 - <<'PY'
import json, os, pathlib, pty, select, socket, subprocess, time, urllib.request
root = pathlib.Path(os.environ['FD0_TEST_ROOT'])
cli = os.environ['FD0']
server_bin = str(pathlib.Path(os.environ['HOME']) / 'go/bin/fd0-server')
with socket.socket() as probe:
    probe.bind(('127.0.0.1', 0)); port = probe.getsockname()[1]
url = f'http://127.0.0.1:{port}'
out = root / 'deployed'
out.mkdir()

def home(name):
    path = root / name
    path.mkdir()
    (path / 'config.toml').write_text(f'[sync]\nserver = "{url}"\non_unlock = false\n')
    return dict(os.environ, FD0_HOME=str(path), FD0_SSH_SOCK=str(root / f'{name}.sock'),
                FD0_AUTO_PIN='1', RECIPE_OUT=str(out))

admin, reader = home('admin'), home('reader')

def run(env, *args, stdin=None, success=True):
    result = subprocess.run([cli, *args], input=stdin, text=True, capture_output=True, env=env, timeout=60)
    if success and result.returncode:
        raise AssertionError(f'{args[:3]} failed: {result.stderr}')
    if not success and not result.returncode:
        raise AssertionError(f'{args[:3]} unexpectedly succeeded')
    return result

def approve(env, name, passphrase):
    # fd0 recipe approve insists on a terminal; give it a pseudo-terminal.
    pid, fd = pty.fork()
    if pid == 0:
        os.execve(cli, [cli, 'recipe', 'approve', name], env)
    output, sent = b'', False
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
            if not sent and b'Passphrase:' in output:
                os.write(fd, passphrase.encode() + b'\n'); sent = True
    _, status = os.waitpid(pid, 0)
    text = output.decode(errors='replace')
    assert os.waitstatus_to_exitcode(status) == 0, text
    assert 'fd0 service deploy' in text and 'cat >' in text, text

def recipe_show(env, name):
    return json.loads(run(env, 'recipe', 'show', name, '--json').stdout)

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

    for env, pw in ((admin, 'admin-passphrase'), (reader, 'reader-passphrase')):
        run(env, 'init', stdin=f'{pw}\n{pw}\n')
        run(env, 'unlock', stdin=f'{pw}\n')
        run(env, 'sync')

    run(admin, 'scope', 'create', '--label', 'shop')
    run(admin, 'service', 'add', 'shop-db', '--scope', 'shop')
    run(admin, 'service', 'set', 'shop-db', 'db-password', '-', '--env', 'DB_PASSWORD', '--scope', 'shop', stdin='RECIPE_CANARY_1')
    run(admin, 'recipe', 'add', 'shop-db/apps', '--scope', 'shop', '--field', 'db-password', '--stdin', 'systemd-env',
        '--for', 'app-1,app-2', '--', '/bin/sh', '-c', 'cat > "$RECIPE_OUT/$FD0_TARGET.env"')
    assert 'not approved' in run(admin, 'service', 'deploy', 'shop-db', success=False).stderr

    # A reader joins and sees the recipe after sync.
    card = run(reader, 'card', 'export').stdout.strip()
    run(admin, 'card', 'import', card, '--label', 'reader', '--yes')
    run(admin, 'scope', 'add-member', 'reader', '--scope', 'shop', '--role', 'reader')
    run(admin, 'sync')
    run(reader, 'sync')
    assert recipe_show(reader, 'shop-db/apps')['approval'] == 'not approved on this device'

    approve(admin, 'shop-db/apps', 'admin-passphrase')
    deployed = run(admin, 'service', 'deploy', 'shop-db')
    assert deployed.stderr.count('command succeeded') == 2, deployed.stderr
    assert 'RECIPE_CANARY_1' not in deployed.stdout + deployed.stderr
    for target in ('app-1', 'app-2'):
        assert (out / f'{target}.env').read_text() == 'DB_PASSWORD="RECIPE_CANARY_1"\n'

    # Results reach the other member without any values.
    run(reader, 'sync')
    shown = recipe_show(reader, 'shop-db/apps')
    assert [r['target'] for r in shown['results']] == ['app-1', 'app-2'], shown
    assert all(r['status'] == 'ok' for r in shown['results']), shown
    assert 'RECIPE_CANARY_1' not in json.dumps(shown)

    # A reader may deploy with its own approval; it cannot publish results.
    (out / 'app-1.env').unlink()
    approve(reader, 'shop-db/apps', 'reader-passphrase')
    by_reader = run(reader, 'service', 'deploy', 'shop-db/apps', '--target', 'app-1')
    assert 'results stay on screen only' in by_reader.stderr, by_reader.stderr
    assert (out / 'app-1.env').read_text() == 'DB_PASSWORD="RECIPE_CANARY_1"\n'
    # … and it cannot change the recipe.
    run(reader, 'recipe', 'edit', 'shop-db/apps', '--field', 'db-password', '--stdin', 'sh',
        '--', '/bin/sh', '-c', 'cat > /tmp/elsewhere', success=False)

    # The admin changes the recipe: the reader's device refuses until it approves again.
    run(admin, 'recipe', 'edit', 'shop-db/apps', '--scope', 'shop', '--field', 'db-password', '--stdin', 'systemd-env',
        '--for', 'app-1,app-2,app-3', '--', '/bin/sh', '-c', 'cat > "$RECIPE_OUT/$FD0_TARGET.env"')
    run(admin, 'sync')
    run(reader, 'sync')
    refused = run(reader, 'service', 'deploy', 'shop-db', success=False)
    assert 'changed since approval' in refused.stderr, refused.stderr

    # A rotation needs no new approval on the admin's device either, once the
    # admin approves its own change.
    approve(admin, 'shop-db/apps', 'admin-passphrase')
    run(admin, 'service', 'set', 'shop-db', 'db-password', '-', '--scope', 'shop', stdin='RECIPE_CANARY_2')
    run(admin, 'service', 'deploy', 'shop-db')
    assert (out / 'app-3.env').read_text() == 'DB_PASSWORD="RECIPE_CANARY_2"\n'
    print('recipes integration: approval, targets, synced results, reader deploy and re-approval verified')
finally:
    server.terminate(); server.wait(timeout=5)
PY
