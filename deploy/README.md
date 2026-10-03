# Deploy

Minimal docker-compose building blocks for the two fd0 services. They bind to
localhost by default. Add your own reverse proxy, TLS, and firewall policy.

```
deploy/
├── server/compose.yml       Just fd0-server
└── witness/compose.yml      Just fd0-witness, points at any fd0-server
```

For the full TLS-terminated production recipe (Caddy + Let's Encrypt + Podman quadlet) see [`docs/HOSTING.md`](../docs/HOSTING.md) — that's how `fd0.sh` itself runs.

## fd0-server

Stores ciphertext and signed event headers. Serves the v1 API on
`127.0.0.1:4048` by default.

Fresh host, no repository checkout:

```sh
mkdir fd0-server
cd fd0-server
curl -fsSLO https://fd0.sh/files/compose.yml
umask 077
printf 'METRICS_TOKEN=%s\n' "$(openssl rand -hex 32)" > .env
case "$(uname -m)" in arm64|aarch64) printf 'FD0_SERVER_IMAGE=%s\n' 'ghcr.io/k2b-dev/fd0-server:latest-arm64' >> .env ;; esac
docker compose up -d
curl http://localhost:4048/health
docker compose logs fd0-server | grep server_pub_hex
```

From this repository:

```sh
cd deploy/server
umask 077
printf 'METRICS_TOKEN=%s\n' "$(openssl rand -hex 32)" > .env
case "$(uname -m)" in arm64|aarch64) printf 'FD0_SERVER_IMAGE=%s\n' 'ghcr.io/k2b-dev/fd0-server:latest-arm64' >> .env ;; esac
docker compose up -d
curl http://localhost:4048/health
docker compose logs fd0-server | grep server_pub_hex
```

Put your TLS terminator on the same host or proxy to `127.0.0.1:4048`, then
point your fd0 client at it:

```toml
# ~/.fd0/config.toml
[sync]
server = "https://your-domain.example"
```

## fd0-witness

Polls one fd0-server's transparency log, archives observed STHs, cosigns consistency-verified observations, and flags divergent roots. Binds to `127.0.0.1:4049` by default.

```sh
cd deploy/witness
umask 077
{
  printf 'SERVER_URL=%s\n' 'https://api.fd0.sh'
  printf 'SERVER_PUB=%s\n' '<64 hex characters obtained out of band>'
  printf 'METRICS_TOKEN=%s\n' "$(openssl rand -hex 32)"
} > .env
case "$(uname -m)" in arm64|aarch64) printf 'FD0_WITNESS_IMAGE=%s\n' 'ghcr.io/valentinkolb/fd0-witness:latest-arm64' >> .env ;; esac
docker compose up -d
curl http://localhost:4049/health
```

The witness auto-discovers chains from `/v1/chains`. A fresh witness requires
the server's 32-byte ed25519 public key as 64 hex characters. Obtain it from
the server operator through a channel independent of the server connection
being monitored. A self-hosted `fd0-server` prints `server_pub_hex` in its
startup log. Existing witness databases continue to use their persisted pin.
`FD0_WITNESS_PIN_ON_FIRST_USE=true` enables unauthenticated first-contact TOFU
for isolated development only; it must not be treated as independent witness
trust.

## Configuration

Both composes are env-driven. Required vars are declared with `:?` so `docker compose up` refuses to start without them. Optional `FD0_*` vars can be added to `.env`; the compose files load that file into the container.

| Service | Required | Useful optionals |
|---|---|---|
| server | `METRICS_TOKEN` | `FD0_SERVER_IMAGE`, `FD0_LABEL`, `FD0_PEERS`, `FD0_PEER_RESOLVE_INTERVAL`, `FD0_REPLICATE_FROM`, `FD0_BIND`, `FD0_DB`, `FD0_RATELIMIT_*` |
| witness | `SERVER_URL`, `SERVER_PUB`, `METRICS_TOKEN` | `FD0_WITNESS_IMAGE`, `FD0_WITNESS_POLL_INTERVAL`, `FD0_WITNESS_CHAINS` |

Current image tags are per architecture: `latest` for amd64 and `latest-arm64`
for arm64. Set `FD0_SERVER_IMAGE` or `FD0_WITNESS_IMAGE` in `.env` when the
default tag is not the one you want. For production, pin a released image tag.

### Redundancy: DR backup

A client writes and reads **exactly one** primary (`[sync].server`) — that one server is the sole ordering authority for every scope, and clients never reconcile two writable authorities. There is no client-side multi-push or read-failover. Malicious-server equivocation is handled by the translog and witness layer. Redundancy comes from a server-side disaster-recovery backup, not a second write target. The design rationale is in [`docs/REPLICATION.md`](../docs/REPLICATION.md).

To run a DR backup:

1. The primary gets `FD0_LABEL` ([a-z0-9-]{0,32}) and lists the standby in `FD0_PEERS` to authorise the pull.
2. The standby is configured with `FD0_REPLICATE_FROM=<primary-url>`. It fetches the primary's `/v1/server-info`, TOFU-pins the primary's signing pubkey, and pulls the primary's chains into a write-once local archive (`backup_*` tables), verifying each STH under the primary's key.
3. The standby **never serves** the backed-up chains and never re-signs them, so it can never become a second authority. Promotion to a new primary is a manual operator ceremony (restore the archive into a fresh identity, re-pin clients).

Each server runs its own `fd0-witness` (poll URL = the local server) so equivocation is detected independently per server.

Full env-var reference per binary: `fd0-server --help`, `fd0-witness --help`.

## Backups

The two named volumes (`fd0-server-data`, `fd0-witness-data`) hold everything irreplaceable:

- `fd0-server-data` — SQLite event store + ed25519 transparency-log signing key
- `fd0-witness-data` — SQLite archive + ed25519 cosign key

Lose either and clients will need to re-pin. Snapshot the volumes (or use `sqlite3 .backup` against the DB files inside) on whatever schedule fits your durability target. The `fd0.sh` production setup uses both hourly VM snapshots and a daily `sqlite3 .backup` cron — see [`docs/HOSTING.md`](../docs/HOSTING.md) for the recipe.

## Multiple instances

To watch a second server, drop a second copy of `witness/compose.yml` in its own directory, set a different `SERVER_URL`, give the volumes different names. Each witness runs as an independent process with its own DB and metrics endpoint.

To run a second server — a DR backup (`FD0_REPLICATE_FROM=<primary-url>`) or an independent primary on its own domain — drop a second copy of `server/compose.yml` with its own volume. Two fd0-servers can coexist on one host as long as their `ports:` don't collide.
