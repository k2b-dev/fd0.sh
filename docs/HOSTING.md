# How fd0.sh is hosted

Reference for the public hosted instance — `https://fd0.sh`, `https://api.fd0.sh`, `https://api2.fd0.sh`, `https://witness.fd0.sh`, `https://witness2.fd0.sh`.

## Operator

- Legal entity: **Kolb Antik GmbH**, Germany ([kolb-antik.com](https://kolb-antik.com))
- Jurisdiction: German civil and commercial law, DSGVO/GDPR
- Source of truth: this repository; published Docker images at `ghcr.io/k2b-dev/` (server, website) and `ghcr.io/valentinkolb/` (witness)

## Topology

A single primary plus a disaster-recovery backup, each in its own data center:

| Hostname | Role | Location | Self-label |
|---|---|---|---|
| `api.fd0.sh`  | Primary | SWU Ulm — Kolb Antik Proxmox cluster | `swu-ulm` |
| `api2.fd0.sh` | DR backup | Hetzner Falkenstein — Hetzner Cloud VM | `hetzner-fsn1` |

Each server runs `fd0-server` against its own SQLite DB and signs its own STHs under its own ed25519 translog key. Each server also has a paired `fd0-witness` (`witness.fd0.sh`, `witness2.fd0.sh`) that archives observed STHs and cosigns consistency-verified observations for that server.

Peer authorization is one-directional. The primary lists the DR backup in `FD0_PEERS`; that authorizes the backup to pull the primary through `FD0_REPLICATE_FROM`. A server may also publish peer metadata in `/v1/server-info`, but clients treat it as informational.

The `fd0` client writes and reads to a **single primary** — `api.fd0.sh`. Clients never reconcile two writable authorities; a client config listing more than one server is a hard error (REPLICATION.md). `api2.fd0.sh` is a **disaster-recovery backup**, not a second write target: it pulls api's chains into a write-once archive via `FD0_REPLICATE_FROM` and never serves them. Malicious-server equivocation remains a translog and witness concern. See REPLICATION.md for the model and TRANSLOG.md §11 for the peer wire format.

## Stack

The primary and the DR backup run different distros, container runtimes, and proxies so a CVE or regression in one component cannot affect both.

| Layer | api.fd0.sh (SWU) | api2.fd0.sh (Hetzner) |
|---|---|---|
| OS | Rocky Linux 10 | Debian 13 (Trixie) |
| Container runtime | Podman 5.x + Quadlet | Docker 29 + Compose v5 |
| Reverse proxy | Caddy 2.x | Traefik 3.x |
| Firewall | Proxmox hypervisor layer | UFW + fail2ban + Hetzner Cloud Firewall |
| TLS | Let's Encrypt via TLS-ALPN-01 (both) ||
| Database | SQLite (both, bundled with the binary) ||
| Binaries | `fd0-server`, `fd0-witness`, `fd0-website` from this repo (both) ||

Build artefacts come from the [release-docker workflow](../.github/workflows/release-docker.yml). Current Docker tags are published per architecture: `latest` for amd64 and `latest-arm64` for arm64.

## Network

- IPv4 + IPv6 dual-stack on every host
- TLS on `443/tcp` + `443/udp` (HTTP/3); HTTP→HTTPS redirect on `80/tcp`
- Certificate renewal handled by the proxy on each host

## What the operator can and cannot see

The zero-knowledge contract in PROTOCOL.md applies to the hosted instance without exception:

| | Visible to operator | Not visible to operator |
|---|---|---|
| Network | TLS-terminated request timing, source IPs, body sizes | Decrypted bodies — ciphertext on the wire and on disk |
| Storage | Ciphertext, signed event headers, chain ids, event timing/order, member public keys, and membership changes | Secret values, secret names, passphrases, private keys, and scope keys |
| Operational | Stop the primary or the backup, change DNS, sign STHs under the server key | Anything in the columns above, even with root on the host |

A server that tries to show different histories to different clients leaves a publishable proof: every STH is signed under the server key; the paired witness cosigns consistency-verified STHs and archives fork evidence such as divergent roots at the same `tree_size`.

## Backups

VM-level snapshots use each provider's primitives:

- **api.fd0.sh (SWU)** — hourly Proxmox snapshots, daily off-site copy to Hetzner S3 object storage in a separate data center. The off-site copy survives a complete SWU incident.
- **api2.fd0.sh (Hetzner)** — daily Hetzner Cloud backups. It is itself the DR backup of api.fd0.sh: its write-once `backup_*` archive, populated by the `FD0_REPLICATE_FROM` pull, holds every event the primary has, so api2 is the off-site copy of api's data.

App-level backups run on both servers:

1. **Daily SQLite snapshots** — `sqlite3 .backup` of `fd0.db` and `witness.db`, gzipped, 30-day rotation. Driven by a systemd timer; output at `/var/backups/fd0/` or `/srv/fd0/backups/`.
2. **Crypto keys off-host** — translog signing key and witness cosign key, exported once and stored in an off-host encrypted vault. These keys are stable for the life of the server; a fresh host restored with the original key needs no re-pinning.

Metrics tokens are rotatable in place and do not need backups.

## Updates

Image updates are manual. The operator pulls a new tag, restarts the service, observes the logs — no auto-update, so a broken or malicious upstream release cannot reach production unobserved. Production pins specific tags once a release line is stable. Schema migrations run on first boot under the new version; the on-disk format is forward-compatible across patch and minor versions per PROTOCOL.md §8.

## Security posture

- Container runtimes confined per OS: SELinux + container-selinux on Rocky; AppArmor + Docker's default seccomp on Debian
- HTTP requests permanently redirected to HTTPS
- `/metrics` bearer-token guarded; missing or wrong token returns `404` so the endpoint does not advertise its existence
- SSH: key-based authentication only, single operator key per host
- Vulnerability monitoring: subscribed to Rocky 10, Debian 13, Podman, Docker, Caddy, and Traefik security advisories; package updates run on a regular cadence

## Incident contact

Security issues affecting the hosted instance or the code: email **mail@valentin-kolb.com** with subject prefix `fd0-security:`. Include the affected version, the construction or code path you believe is wrong, and a reproducer. Non-security operational issues go to GitHub Issues.

DSGVO/GDPR data-subject requests use the same address. fd0's zero-knowledge design means the operator cannot decrypt user data — most requests resolve to "the ciphertext you can already access from your own client; deletion is a chain operation that originates on your device."

---

## Self-hosting

The setup above is reproducible. Two shapes are supported.

### Single server

```bash
mkdir fd0-server
cd fd0-server
curl -fsSLO https://fd0.sh/files/compose.yml
umask 077
printf 'METRICS_TOKEN=%s\n' "$(openssl rand -hex 32)" > .env
case "$(uname -m)" in arm64|aarch64) printf 'FD0_SERVER_IMAGE=%s\n' 'ghcr.io/k2b-dev/fd0-server:latest-arm64' >> .env ;; esac
docker compose up -d
```

Client config:

```toml
# ~/.fd0/config.toml
[sync]
server = "https://your-domain.example"
```

The compose file binds `127.0.0.1:4048` by default. Add your own TLS
terminator in front before pointing real clients at it. The quickstart writes
the arm64 image override when it detects an ARM host. For production, pin a
released image tag instead of tracking `latest`.

The same server compose file is also kept in `deploy/server/compose.yml` for
repository checkouts.

### Primary + DR backup

The shape `fd0.sh` itself runs: one primary that serves clients, one standby that pulls the primary into a write-once archive.

**1. DNS.** Point `api.example.com` (primary) and `api2.example.com` (DR backup) at their respective VMs.

**2. Primary (server A).** Lists the standby in `FD0_PEERS` to authorise its pull.

```yaml
environment:
  FD0_LABEL: site-a
  FD0_PEERS: https://api2.example.com
  FD0_METRICS_TOKEN: ${METRICS_TOKEN:?}
```

**3. DR backup (server B).** Pulls the primary read-only via `FD0_REPLICATE_FROM`. It does not need `FD0_PEERS` for that pull.

```yaml
environment:
  FD0_LABEL: site-b
  FD0_REPLICATE_FROM: https://api.example.com
  FD0_METRICS_TOKEN: ${METRICS_TOKEN:?}
```

On boot, the primary resolves the standby's `/v1/server-info`, TOFU-pins its pubkey, and authorizes the standby pull because the standby URL is listed in the primary's `FD0_PEERS`. Check the published peer list:

```bash
python3 -m venv .venv-fd0-cbor
. .venv-fd0-cbor/bin/activate
python -m pip install cbor2
curl -fsS https://api.example.com/v1/server-info \
  | python -c 'import sys,cbor2; d=cbor2.loads(sys.stdin.buffer.read()); print(d.get("label"), d.get("peers"))'
curl -fsS https://api2.example.com/v1/server-info \
  | python -c 'import sys,cbor2; d=cbor2.loads(sys.stdin.buffer.read()); print(d.get("label"), d.get("peers"))'
```

**4. Client config.**

```toml
# ~/.fd0/config.toml
[sync]
server = "https://api.example.com"   # the single primary
```

The client writes and reads only the primary — one ordering authority per scope, so nothing can diverge. The second server (`api2.example.com`) is a DR backup that pulls the primary via `FD0_REPLICATE_FROM` (step below); clients never write to it. Listing two servers here is a hard error.

**5. Witness per server (optional).** Each server has its own translog under its own key, so each needs its own witness to archive observations and cosign consistency-verified STHs.

```yaml
# witness-a — paired with server A
FD0_WITNESS_SERVER_URL: https://api.example.com
FD0_WITNESS_SERVER_PUB: <server-a public key obtained out of band>

# witness-b — paired with server B
FD0_WITNESS_SERVER_URL: https://api2.example.com
FD0_WITNESS_SERVER_PUB: <server-b public key obtained out of band>
```

`fd0-server` prints `server_pub_hex` at startup. Transfer that public key to
the witness through a channel independent of the API connection. A fresh
witness refuses to start without it; an existing witness continues to use its
persisted pin.

### Operational notes

- **One write authority.** Clients write/read a single primary, so there is no multi-push and no client-driven propagation between servers. Redundancy is the server-side **DR backup** below (the standby pulls the primary read-only). Live server-to-server gossip into the serving tables remains a non-goal (REPLICATION.md §5).
- **DR backup (standby).** A server with `FD0_REPLICATE_FROM=<primary-url>` mirrors that primary's chains (encrypted events + signed STHs) into a write-once local archive (`backup_*` tables), verifying each STH under the primary's key before storing it. The primary must list the standby in its `FD0_PEERS` to authorise the pull. The standby never serves the backup; it is disaster-recovery only — if the primary's disk is lost, the standby holds every event. `FD0_REPLICATE_INTERVAL` (default 30s) sets the cadence; `FD0_PEER_RESOLVE_INTERVAL` sets how fast the primary pins the standby (default 1h — set short when bringing the pair up). Promotion (restoring from the archive) is an operator ceremony, not automatic.
- **Adding redundancy.** Redundancy is a DR-backup peer, not a second write target — clients always point at the one primary (`[sync].server`) and never list extra URLs. To add a standby, stand up a server with `FD0_REPLICATE_FROM=<primary-url>`, add its URL to the primary's `FD0_PEERS`, and restart the primary. The TOFU-pin establishes on the next resolver tick (default 1h), which authorises the pull.
- **Removing a backup.** Stop the container and remove its URL from the primary's `FD0_PEERS`. On the next boot the primary prunes any pinned peer no longer in its `FD0_PEERS` — this also revokes that peer's replication-pull authorization, so the stale row must not linger. (Restart the primary to apply; the prune is automatic.) Clients are unaffected: they only ever held the primary's URL.
- **Rotating a server's ed25519 key.** Same ceremony as a single-server rotation (TRANSLOG.md §4.3). Every client and every peering server must re-pin. Peers refuse silent rotation; the operator wipes the row (`DELETE FROM peers WHERE url = ?`) and the resolver re-TOFUs on the next tick.
- **Per-server backups.** Each server has its own SQLite DB and its own ed25519 key. Losing the standby's data costs only its DR archive; losing the primary's disk is recoverable from the standby's `backup_*` archive via the promotion ceremony (REPLICATION.md §3).

The compose examples work behind any reverse proxy that terminates TLS and forwards to the container's port. To reproduce `fd0.sh` end-to-end, follow the Stack section above with the matching distro / runtime / proxy on each host.

The server uses the direct peer address for per-IP rate limits by default. If
the reverse proxy runs on another address, set `FD0_TRUSTED_PROXY_CIDRS` to
that proxy's exact CIDR, for example `10.20.0.5/32`. fd0 then accepts a single
IP in `X-Forwarded-For` only from that network. Do not trust a client-facing
network or a comma-separated forwarding chain.
