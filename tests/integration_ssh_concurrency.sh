#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/integration_isolation.sh"
fd0_test_require_isolation
trap fd0_test_stop_agents EXIT
python3 - <<'PY'
import concurrent.futures, fcntl, os, pathlib, socket, struct, subprocess, threading, time
root = pathlib.Path(os.environ['FD0_TEST_ROOT'])
home = root / 'ssh-concurrency'
home.mkdir()
env = dict(os.environ, FD0_HOME=str(home), FD0_SSH_SOCK=str(root / 'ssh.sock'))
(home / 'config.toml').write_text('[sync]\non_unlock = false\n[client]\nlock_wait = "100ms"\n')
cli = os.environ['FD0']
def run(*args, stdin=None):
    r = subprocess.run([cli, *args], input=stdin, text=True, capture_output=True, env=env, timeout=30)
    assert r.returncode == 0, f'{args[:2]} failed: {r.stderr}'
    return r.stdout
run('init', stdin='synthetic-password\nsynthetic-password\n')
run('unlock', stdin='synthetic-password\n')
run('scope', 'create', '--label', 'work')
run('key', 'add', 'first', '--scope', 'work')
run('key', 'add', 'second', '--scope', 'work')
def exact(c, n):
    data = b''
    while len(data) < n:
        part = c.recv(n-len(data))
        assert part, 'unexpected EOF'
        data += part
    return data
def request(c, payload):
    c.sendall(struct.pack('>I', len(payload))+payload)
    return exact(c, struct.unpack('>I', exact(c,4))[0])
def connect():
    c=socket.socket(socket.AF_UNIX, socket.SOCK_STREAM);c.settimeout(20);c.connect(env['FD0_SSH_SOCK']);return c
def string(b): return struct.pack('>I',len(b))+b
with connect() as c:
    identities=request(c,b'\x0b')
assert identities[0]==12 and struct.unpack('>I',identities[1:5])[0]==2
size=struct.unpack('>I',identities[5:9])[0]
public=identities[9:9+size]
sign=b'\x0d'+string(public)+string(b'synthetic challenge')+struct.pack('>I',0)
# Longer than the former five-second budget, and longer than the configured
# interactive budget. This is the same flock held by CLI writes and sync.
with open(home / '.lock','a') as lock:
    fcntl.flock(lock,fcntl.LOCK_EX)
    barrier=threading.Barrier(9)
    def probe(i):
        with connect() as c:
            barrier.wait()
            return request(c,b'\x0b' if i%2==0 else sign)
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        futures=[pool.submit(probe,i) for i in range(8)]
        barrier.wait();time.sleep(6)
        assert not any(f.done() for f in futures), 'request failed before vault lock released'
        fcntl.flock(lock,fcntl.LOCK_UN)
        for i,f in enumerate(futures):
            response=f.result(timeout=20)
            assert response[0]==(12 if i%2==0 else 14), 'parallel list/sign failed'
            if i%2==0: assert struct.unpack('>I',response[1:5])[0]==2
# Existing connections must observe subsequent key changes and vault lock.
with connect() as c:
    run('key','add','third','--scope','work')
    assert struct.unpack('>I',request(c,b'\x0b')[1:5])[0]==3
    run('key','rm','third','--scope','work')
    assert struct.unpack('>I',request(c,b'\x0b')[1:5])[0]==2
    run('lock')
    assert struct.unpack('>I',request(c,b'\x0b')[1:5])[0]==0
    assert request(c,sign)[0]==5
print('PASS: parallel SSH list/sign survives vault contention; fresh keys and lock on existing connections')
PY
