#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/integration_isolation.sh"
fd0_test_require_isolation
trap fd0_test_stop_agents EXIT
python3 - <<'PY'
import json, os, pathlib, socket, subprocess, time, urllib.request
root = pathlib.Path(os.environ['FD0_TEST_ROOT'])
home = root / 'vault'
home.mkdir()
env = dict(os.environ, FD0_HOME=str(home), FD0_SSH_SOCK=str(root / 'ssh.sock'), FD0_AUTO_PIN='1')
cli = os.environ['FD0']
server_bin = str(pathlib.Path(os.environ['HOME']) / 'go/bin/fd0-server')
with socket.socket() as probe:
    probe.bind(('127.0.0.1', 0)); port = probe.getsockname()[1]
url = f'http://127.0.0.1:{port}'
(home / 'config.toml').write_text(f'[sync]\nserver = "{url}"\non_unlock = false\n')
def run(*args, stdin=None, success=True):
    result = subprocess.run([cli, *args], input=stdin, text=True, capture_output=True, env=env, timeout=30)
    if success and result.returncode:
        raise AssertionError(f'{args[:2]} failed: {result.stderr}')
    if not success and not result.returncode: raise AssertionError(f'{args[:2]} unexpectedly succeeded')
    return result
log = open(root / 'server.log', 'w')
def start():
    process = subprocess.Popen([server_bin, '--bind', f'127.0.0.1:{port}', '--db', str(root / 'server.db'), '--no-ratelimit'], env=env, stdout=log, stderr=log)
    for attempt in range(100):
        try:
            urllib.request.urlopen(url + '/health', timeout=.2).close(); return process
        except Exception: time.sleep(.05)
    raise AssertionError('isolated server did not start')
server = start()
try:
    run('init', stdin='synthetic-password\nsynthetic-password\n')
    run('unlock', stdin='synthetic-password\n')
    for scope in ['work', 'destination']:
        run('scope', 'create', '--label', scope)
    run('secret', 'set', 'token', '-', '--scope', 'work', stdin='ORGANIZATION_STDIO_CANARY')
    run('sync')
    inventory = json.loads(run('item', 'list', '--scope', 'work', '--json').stdout)
    item = inventory[0]
    run('item', 'tags', 'add', item['id'], '--scope', 'work', '--tag', 'Prod')
    # Destination writes survive offline, but the source must not be archived.
    server.terminate(); server.wait(timeout=5)
    run('secret', 'move', 'token', '--scope', 'work', '--to-scope', 'destination', success=False)
    assert len(json.loads(run('item', 'list', '--scope', 'work', '--json').stdout)) == 1
    server = start()
    run('secret', 'move', 'token', '--scope', 'work', '--to-scope', 'destination')
    assert json.loads(run('item', 'list', '--scope', 'work', '--json').stdout) == []
    moved = json.loads(run('item', 'list', '--scope', 'destination', '--json').stdout)[0]
    assert moved['tags'] == ['Prod']
    assert 'ORGANIZATION_STDIO_CANARY' in run('secret', 'get', 'token', '--scope', 'destination').stdout
    # Use the real stdio process; both stdout and stderr are model-visible.
    mcp = subprocess.Popen([cli, 'organize', 'serve', '--scope', 'destination', '--allow', 'tags', '--ttl', '1m'], env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    transcript = []
    def rpc(method, params):
        mcp.stdin.write(json.dumps({'jsonrpc':'2.0','id':len(transcript)+1,'method':method,'params':params})+'\n'); mcp.stdin.flush()
        line = mcp.stdout.readline(); assert line, 'stdio server exited'
        transcript.append(line); return json.loads(line)
    def call(name, args):
        reply = rpc('tools/call', {'name':name, 'arguments':args})['result']
        return reply, reply['content'][0]['text']
    rpc('initialize', {'protocolVersion':'2025-06-18','capabilities':{},'clientInfo':{'name':'isolated-test','version':'1'}})
    _, info = call('organization_session', {}); info = json.loads(info)
    _, listing = call('organization_list', {}); current = json.loads(listing)['items'][0]
    _, proposed = call('organization_propose', {'changes':[{'scopeId':current['scopeId'],'id':current['id'],'revision':current['revision'],'tags':['Reviewed']}]})
    proposed = json.loads(proposed); plan = proposed['plan']
    denied, _ = call('organization_execute', {'planId':plan['id']}); assert denied['isError']
    run('organize','approve',info['sessionId'],plan['id'],'--digest',proposed['digest'])
    result, _ = call('organization_execute', {'planId':plan['id']}); assert not result['isError']
    denied, _ = call('secret.get', {'name':'token'}); assert denied['isError']
    mcp.stdin.close(); mcp.wait(timeout=5)
    transcript.append(mcp.stderr.read())
    assert not any('ORGANIZATION_STDIO_CANARY' in text for text in transcript)
    assert json.loads(run('item','list','--scope','destination','--json').stdout)[0]['tags'] == ['Reviewed']
    current = json.loads(run('item','list','--scope','destination','--json').stdout)[0]
    preview = run('item','batch','--scope','destination','--id',current['id'],'--operation','add','--tag','CLI batch','--dry-run').stdout
    assert json.loads(preview)['scopes'], 'preview did not bind scope policies'
    reviewed_file = root / 'reviewed.json'; reviewed_file.write_text(preview)
    assert 'CLI batch' not in json.loads(run('item','list','--scope','destination','--json').stdout)[0]['tags']
    run('item','batch','--input',str(reviewed_file))
    assert 'CLI batch' in json.loads(run('item','list','--scope','destination','--json').stdout)[0]['tags']

    # The actual Desktop bridge preserves literal values and rejects stale tags.
    (home / '.desktop-isolated').write_text('fd0-desktop-isolated-v1\n')
    bridge_env = dict(env, FD0_DESKTOP_MODE='isolated', FD0_AGENT_SYNC_DISABLED='1')
    bridge_bin = str(pathlib.Path(os.environ['HOME']) / 'go/bin/fd0-desktop-bridge')
    def bridge(method, params):
        result = subprocess.run([bridge_bin], input=json.dumps({'version':1,'id':'test','method':method,'params':params})+'\n', text=True, capture_output=True, env=bridge_env, timeout=15)
        assert result.returncode == 0, 'isolated bridge failed'
        return json.loads(result.stdout)
    scope_id = current['scopeId']
    assert 'error' not in bridge('secret.save', {'scopeId':scope_id,'name':'bridge-token','value':'-','create':True})
    assert run('secret','get','bridge-token','--scope','destination').stdout.strip() == '-'
    assert 'error' not in bridge('item.tags', {'scopeId':scope_id,'name':'bridge-token','tags':['Desktop'],'expectedTags':[]})
    assert bridge('item.tags', {'scopeId':scope_id,'name':'bridge-token','tags':['Stale'],'expectedTags':[]})['error']['code'] == 'conflict'
    assert 'error' not in bridge('secret.save', {'scopeId':scope_id,'oldName':'bridge-token','name':'bridge-renamed','value':'literal\nvalue'})
    assert run('secret','get','bridge-renamed','--scope','destination').stdout.strip() == 'literal\nvalue'
    assert next(item for item in json.loads(run('item','list','--scope','destination','--json').stdout) if item['name'] == 'bridge-renamed')['tags'] == ['Desktop']
    print('organization integration: verified offline retention, acknowledged move/resume, tags and real restricted stdio approval without value output')
finally:
    if 'mcp' in locals() and mcp.poll() is None: mcp.terminate(); mcp.wait(timeout=5)
    server.terminate(); server.wait(timeout=5); log.close()
PY
